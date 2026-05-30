"""
passive.py

Implements the passive scan mode. Launches a Chromium browser instance via
Playwright routed through an in-process mitmproxy, navigates to the target URL,
and captures every API response header as the browser makes requests naturally.

Unlike active mode, passive mode observes real browser traffic including
authenticated requests, dynamically loaded API calls, and third-party API
endpoints that would not be discoverable from the base URL alone.

This module is only importable and callable when is_passive_available() is True.
On headless installations it is never imported because the --passive flag is not
registered in sentry/main.py.

Classes:
    PassiveScanner: Manages the browser session and proxy lifecycle.

Functions:
    run: Entry point called by sentry/main.py for passive-mode scans.
    _build_results_dict: Serialise passive scan results into a JSON-compatible structure.
    _render_endpoint: Print a single EndpointResult to a Rich Console.
    _render_results: Print all passive scan results to a Rich Console.
"""

from __future__ import annotations

import io
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from rich import box
from rich.console import Console
from rich.table import Table

from sentry import __version__
from sentry.config.headers import AUTH_SECURITY_FLAGS
from sentry.core.analyzer import EndpointResult, analyze_headers
from sentry.core.interceptor import run_proxy
from sentry.core.reporter import save_html_report, save_pdf_report, save_report
from sentry.core.storage import CaptureStore

console = Console()

_STATUS_STYLES: dict[str, str] = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}

_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "WARN": "yellow",
    "LOW": "cyan",
}

_GRADE_STYLES: dict[str, str] = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}

_PROXY_HOST = "127.0.0.1"
_PROXY_PORT = 8080


def _ensure_chromium() -> None:
    """
    Install the Playwright Chromium browser if it is not already present.

    Called once at the start of every passive scan. On systems where Chromium
    was installed by the .deb postinst or a prior run, the executable check
    returns immediately. On a fresh pip install where the user has not run
    'sentry-install-browser', this performs the download automatically so no
    manual post-install step is required.

    Prints a one-time informational message during download. If the install
    fails (no network, permission denied) a WARN is printed and the scan
    proceeds — Playwright will then raise its own error at launch time with
    instructions to fix it.
    """
    from pathlib import Path
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as pw:
            executable = pw.chromium.executable_path
        if Path(executable).exists():
            return
    except Exception:
        pass

    console.print(
        "[cyan][[INFO]][/cyan] Chromium browser not found. "
        "Running one-time setup — this may take a minute..."
    )
    try:
        # Use sys.executable -m playwright rather than a bare 'playwright'
        # command: after pip install inside a venv the module is importable but
        # the playwright script may not yet be on PATH.
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
        )
        console.print("[green][[PASS]][/green] Chromium installed successfully.")
    except Exception as exc:
        console.print(
            f"[yellow][[WARN]][/yellow] Could not auto-install Chromium: {exc}"
        )
        console.print(
            "[yellow][[WARN]][/yellow] Run 'playwright install chromium' manually and retry."
        )


class PassiveScanner:
    """
    Manages the Playwright browser session and mitmproxy lifecycle for passive mode.

    Starts the in-process mitmproxy (core.interceptor.run_proxy), configures
    Playwright to route all traffic through it, opens the target URL, waits for
    the page close event or a timeout, shuts down the proxy, then passes captured
    headers to the analyzer.

    Attributes:
        url (str): The base URL to open in the browser.
        timeout (int): Maximum seconds to keep the browser open before auto-closing.
        verbose (bool): When True, log each captured response URL to the terminal.
        store (Optional[CaptureStore]): Shared store populated during scan(); None before.

    Example:
        scanner = PassiveScanner(url="https://example.com", timeout=120)
        results = scanner.scan()
    """

    def __init__(
        self,
        url: str,
        timeout: int = 120,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the passive scanner with a target URL and session options.

        Args:
            url (str): The URL to open in Chromium at session start.
            timeout (int): Seconds to keep the browser open before auto-closing.
                           Gives the user time to navigate and trigger API calls.
            verbose (bool): Echo captured response URLs to the terminal when True.
        """
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.store: Optional[CaptureStore] = None

    def scan(self) -> list[EndpointResult]:
        """
        Run the passive capture session and return analysis results.

        Starts mitmproxy, launches Chromium with the proxy configured, navigates
        to the target URL, waits for the browser window to close or the timeout
        to expire, shuts the proxy down, then analyses all captured API responses.

        Returns:
            list[EndpointResult]: One result per captured API endpoint, in the
                                  order they were intercepted.
        """
        from playwright.sync_api import TimeoutError as PlaywrightTimeout, sync_playwright

        self.store = CaptureStore()
        parsed = urlparse(self.url)
        target_host = parsed.hostname or parsed.netloc

        _ensure_chromium()
        console.print(f"[cyan][[INFO]][/cyan] Starting proxy on {_PROXY_HOST}:{_PROXY_PORT}")
        master = run_proxy(
            store=self.store,
            target_host=target_host,
            host=_PROXY_HOST,
            port=_PROXY_PORT,
        )

        # Give the proxy event loop a moment to bind and accept connections before
        # the browser starts sending traffic through it.
        time.sleep(1)

        console.print(f"[cyan][[INFO]][/cyan] Launching Chromium -> {self.url}")
        console.print(
            "[yellow][[WARN]][/yellow] TLS certificate validation is DISABLED for all "
            "sites in this browser session. Do not log into personal accounts or "
            "browse unrelated sites during the scan."
        )
        console.print(
            f"[cyan][[INFO]][/cyan] Browse freely. "
            f"Close the window or wait {self.timeout}s for the session to end."
        )

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=False,
                    proxy={"server": f"http://{_PROXY_HOST}:{_PROXY_PORT}"},
                    args=["--ignore-certificate-errors"],
                )
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                try:
                    page.goto(self.url, timeout=30000)
                except PlaywrightTimeout:
                    console.print(
                        "[yellow][[WARN]][/yellow] Initial page load timed out — "
                        "continuing capture session"
                    )
                except Exception:
                    # Navigation errors (DNS failure, refused connection) are non-fatal;
                    # the proxy capture session still runs for any subsequent navigations.
                    pass

                # Block until the user closes the window or the timeout fires.
                try:
                    page.wait_for_event("close", timeout=self.timeout * 1000)
                    console.print("[cyan][[INFO]][/cyan] Browser window closed — ending session")
                except PlaywrightTimeout:
                    console.print(
                        f"[cyan][[INFO]][/cyan] Session timeout ({self.timeout}s) reached — closing browser"
                    )
                except Exception:
                    pass

                try:
                    browser.close()
                except Exception:
                    pass

        finally:
            master.shutdown()
            # Allow the proxy thread to flush any in-flight captured responses before
            # we read from the store.
            time.sleep(0.5)

        captured = self.store.all()
        console.print(
            f"[cyan][[INFO]][/cyan] Captured {len(captured)} API response(s). Analysing..."
        )

        results: list[EndpointResult] = []
        for resp in captured:
            if self.verbose:
                console.print(f"[cyan][[INFO]][/cyan] Analysing: {resp.url}")
            result = analyze_headers(
                url=resp.url,
                response_headers=resp.headers,
                status_code=resp.status_code,
                request_headers=resp.request_headers or None,
                body_sample=resp.body_sample or None,
            )
            results.append(result)

        return results


def _build_results_dict(
    results: list[EndpointResult],
    scan_target: str,
) -> dict:
    """
    Serialise passive scan results into a JSON-compatible dict for report.json.

    Args:
        results (list[EndpointResult]): Completed endpoint analysis objects.
        scan_target (str): Human-readable label for this scan session.

    Returns:
        dict: Fully serialisable dict containing scan metadata and per-endpoint data.
    """
    return {
        "scan_type": "passive",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "sentry_version": __version__,
        "target": scan_target,
        "total_captured": len(results),
        "results": [
            {
                "url": r.url,
                "score": r.score,
                "grade": r.grade,
                "api_type": r.api_type,
                "findings": [
                    {
                        "name": f.name,
                        "status": f.status,
                        "severity": f.severity,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "actual_value": f.actual_value,
                    }
                    for f in r.findings
                ],
                "auth_findings": [
                    {
                        "auth_type": af.auth_type,
                        "flags": af.flags,
                        "details": af.details,
                        "token_info": af.token_info,
                    }
                    for af in r.auth_findings
                ],
                "raw_headers": r.raw_headers,
            }
            for r in results
        ],
    }


def _render_endpoint(con: Console, result: EndpointResult) -> None:
    """
    Render a single EndpointResult as a header findings table.

    Args:
        con (Console): Rich Console to write output to.
        result (EndpointResult): Completed analysis for one URL.
    """
    grade_style = _GRADE_STYLES.get(result.grade, "white")
    con.print(f"\n[bold]--- {result.url} ---[/bold]")
    con.print(
        f"API Type: [cyan]{result.api_type}[/cyan]   "
        f"Score: [{grade_style}]{result.score}/100[/{grade_style}]   "
        f"Grade: [{grade_style}]{result.grade}[/{grade_style}]"
    )

    con.print("\n[bold]Security Headers[/bold]")
    hdr_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    hdr_table.add_column("Header", min_width=30)
    hdr_table.add_column("Status", width=8)
    hdr_table.add_column("Severity", width=10)
    hdr_table.add_column("Detail")

    for f in result.findings:
        status_style = _STATUS_STYLES.get(f.status, "white")
        sev_style = _SEVERITY_STYLES.get(f.severity, "white")
        detail = f.actual_value if f.actual_value else f.description
        hdr_table.add_row(
            f.name,
            f"[{status_style}][{f.status}][/{status_style}]",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            detail,
        )
    con.print(hdr_table)

    if result.auth_findings:
        con.print("[bold]Authentication[/bold]")
        auth_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
        auth_table.add_column("Mechanism", width=14)
        auth_table.add_column("Severity", width=10)
        auth_table.add_column("Detail")

        for af in result.auth_findings:
            if af.flags:
                for flag_id in af.flags:
                    flag_def = AUTH_SECURITY_FLAGS.get(flag_id)
                    sev = flag_def.severity if flag_def else "WARN"
                    desc = flag_def.description if flag_def else flag_id
                    sev_style = _SEVERITY_STYLES.get(sev, "yellow")
                    auth_table.add_row(
                        af.auth_type,
                        f"[{sev_style}]{sev}[/{sev_style}]",
                        f"[{sev_style}][[WARN]][/{sev_style}] {desc}",
                    )
            else:
                details_text = af.details or "No misconfigurations detected"
                auth_table.add_row(
                    af.auth_type,
                    "[green]PASS[/green]",
                    f"[green][[PASS]][/green] {details_text}",
                )
        con.print(auth_table)
    else:
        con.print("[cyan][[INFO]][/cyan] No authentication mechanism detected")


def _render_results(
    target_console: Console,
    results: list[EndpointResult],
    output_format: str,
    results_dict: Optional[dict] = None,
) -> None:
    """
    Print all passive scan results to target_console in the requested format.

    Args:
        target_console (Console): Rich Console to write to (may be a StringIO
            buffer console for report.txt capture).
        results (list[EndpointResult]): Completed endpoint analyses.
        output_format (str): One of 'table', 'json', 'html', 'pdf'.
            html and pdf render as table to terminal; the file is saved by
            the caller after _render_results returns.
        results_dict (Optional[dict]): Pre-built results dict; used for JSON
            output to avoid rebuilding. Built from results if not provided.
    """
    import json as _json

    if output_format == "json":
        data = results_dict or _build_results_dict(results, "passive_session")
        target_console.print(_json.dumps(data, indent=2, default=str))
        return

    target_console.print("\n[bold]Sentry -- Passive Scan Results[/bold]")

    if not results:
        target_console.print(
            "[yellow][[WARN]][/yellow] No API responses were captured. "
            "The session may have been too short or no API traffic matched the filter."
        )
        return

    for result in results:
        _render_endpoint(target_console, result)

    avg_score = sum(r.score for r in results) // len(results)
    fail_urls = sum(1 for r in results if any(f.status == "FAIL" for f in r.findings))
    target_console.print("\n[bold]Summary[/bold]")
    target_console.print(
        f"  Captured: [cyan]{len(results)}[/cyan] API endpoint(s)   "
        f"Avg Score: {avg_score}/100"
    )
    if fail_urls:
        target_console.print(
            f"  [yellow][[!]][/yellow] {fail_urls} endpoint(s) have FAIL findings"
        )


def run(config: dict) -> None:
    """
    Entry point for passive-mode scans called by sentry/main.py.

    Instantiates PassiveScanner, runs the browser session, renders results to
    the terminal in the requested format, and saves the report via
    core.reporter.save_report() with target='passive_session'.

    Args:
        config (dict): Scan configuration dict from sentry/main.py._run(),
                       containing keys: url, output, save, timeout, verbose.
                       Passive mode always uses a single URL; file-based batch
                       input is not supported in this mode.
    """
    url: str = config["url"]
    output: str = config.get("output", "table")
    save_root: Optional[Path] = config.get("save")
    timeout: int = config.get("timeout", 120)
    verbose: bool = config.get("verbose", False)

    console.print(f"\n[bold]Sentry -- Passive Scan[/bold]")
    console.print(f"[cyan][[INFO]][/cyan] Target: {url}")

    scanner = PassiveScanner(url=url, timeout=timeout, verbose=verbose)
    results = scanner.scan()

    results_dict = _build_results_dict(results, "passive_session")

    _render_results(console, results, output, results_dict)

    text_buf = io.StringIO()
    text_console = Console(file=text_buf, no_color=True, width=120)
    _render_results(text_console, results, "table", results_dict)
    text_output = text_buf.getvalue()

    report_dir = save_report(
        target="passive_session",
        results=results_dict,
        text_output=text_output,
        save_root=save_root,
    )

    if output == "html":
        save_html_report(results_dict, report_dir)
    elif output == "pdf":
        save_pdf_report(results_dict, report_dir)
