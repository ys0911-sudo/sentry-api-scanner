"""
active.py

Implements the active scan mode. Sends direct HTTP requests to one or more
target URLs, captures the response headers, and passes them to the analyzer.
This mode requires no browser or proxy — it uses the requests library and
is therefore available on all installation types including headless servers.

When --file is passed the URLs are read one per line; when --url is used a
single URL is scanned. Both paths produce the same EndpointResult format and
are saved via core/reporter.py after all URLs are processed.

Classes:
    ActiveScanner: Orchestrates HTTP requests and analysis for active mode.

Functions:
    run: Entry point called by sentry/main.py for active-mode scans.
    load_urls_from_file: Read and validate a URL list from a plain-text file.
    _build_results_dict: Serialise scan results into a JSON-compatible structure.
    _render_results: Print scan results to a Rich Console in the requested format.
    _render_endpoint: Print a single EndpointResult to a Rich Console.
"""

from __future__ import annotations

import io
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich import box
from rich.table import Table

from sentry import __version__
from sentry.config.headers import AUTH_SECURITY_FLAGS
from sentry.core.analyzer import EndpointResult, analyze_headers
from sentry.core.reporter import save_html_report, save_pdf_report, save_report

console = Console()

_STATUS_STYLES: dict[str, str] = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}

# Maps severity names to Rich style strings for consistent colouring
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


class ActiveScanner:
    """
    Orchestrates HTTP requests and header analysis for active scan mode.

    Iterates over the target URL list, makes a GET request to each URL (with
    configurable timeout and SSL verification), then forwards the response
    headers to core.analyzer.analyze_headers(). Results are aggregated and
    returned to the caller for rendering and report saving.

    Connection errors, timeouts, and SSL failures are caught per-URL; they
    are recorded in self.errors and do not abort the remaining scan.

    Attributes:
        urls (list[str]): Target URLs to scan.
        timeout (int): Per-request timeout in seconds.
        verify_ssl (bool): Whether to verify TLS certificates.
        verbose (bool): When True, print each request URL as it is made.
        errors (dict[str, str]): Maps URLs that failed to their error message.
            Populated by scan(); empty before the first call.

    Example:
        scanner = ActiveScanner(urls=["https://api.example.com"], timeout=30)
        results = scanner.scan()
    """

    # Default User-Agent: identifies the tool without advertising "security scanner",
    # which can trigger WAF blocks and appear in target access logs.
    _DEFAULT_UA = f"sentryscan/{__version__}"

    def __init__(
        self,
        urls: list[str],
        timeout: int = 30,
        verify_ssl: bool = True,
        verbose: bool = False,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Initialise the scanner with a target list and request options.

        Args:
            urls (list[str]): One or more target URLs.
            timeout (int): Per-request timeout in seconds.
            verify_ssl (bool): Verify TLS certificates when True.
            verbose (bool): Echo each request URL to the terminal when True.
            user_agent (Optional[str]): Override the HTTP User-Agent header.
                Defaults to a neutral string that does not advertise the tool
                as a security scanner to avoid WAF triggers and log noise.
        """
        self.urls = urls
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.user_agent = user_agent or self._DEFAULT_UA
        self.errors: dict[str, str] = {}

    def scan(self) -> list[EndpointResult]:
        """
        Execute the active scan against all target URLs.

        Makes an HTTP GET request to each URL, captures response headers, and
        passes them through core.analyzer.analyze_headers(). Connection failures
        and timeouts are caught, recorded in self.errors, and skipped — they
        do not appear in the returned results list.

        Returns:
            list[EndpointResult]: One result per successfully scanned URL, in
                the same order as self.urls (minus errored entries).

        Raises:
            Nothing — all request-level errors are captured in self.errors.
        """
        results: list[EndpointResult] = []

        # The user explicitly opted in to skipping verification; suppress the
        # urllib3 warning that would otherwise fire on every request.
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = requests.Session()
        session.headers["User-Agent"] = self.user_agent

        for url in self.urls:
            if self.verbose:
                console.print(f"[cyan][[INFO]][/cyan] Requesting: {url}")
            try:
                response = session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
                body_sample = response.text[:2048] if response.text else None

                # Send an OPTIONS preflight with a probe origin to surface CORS
                # misconfiguration. The probe origin is deliberately invalid so it
                # can never be a legitimately whitelisted value; any reflection of
                # it is therefore a blind-reflection bug.
                merged_headers = dict(response.headers)
                probe_request_headers: dict[str, str] = {}
                _probe_origin = "https://sentry-probe.invalid"
                try:
                    options_resp = session.options(
                        url,
                        headers={
                            "Origin": _probe_origin,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "Authorization, Content-Type",
                        },
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False,
                    )
                    # Merge only CORS-relevant headers from the OPTIONS response
                    # so they reach _analyze_cors() without overwriting other headers.
                    for k, v in options_resp.headers.items():
                        kl = k.lower()
                        if kl.startswith("access-control") or kl == "vary":
                            merged_headers[k] = v
                    probe_request_headers = {"origin": _probe_origin}
                except Exception:
                    pass

                result = analyze_headers(
                    url=url,
                    response_headers=merged_headers,
                    body_sample=body_sample,
                    status_code=response.status_code,
                    request_headers=probe_request_headers or None,
                )
                results.append(result)
            except requests.exceptions.SSLError as exc:
                self.errors[url] = f"SSL error: {exc}"
                console.print(
                    f"[red][[FAIL]][/red] {url}: SSL certificate error "
                    "(try --insecure to skip verification)"
                )
            except requests.exceptions.ConnectionError:
                self.errors[url] = "Connection refused or host unreachable"
                console.print(f"[red][[FAIL]][/red] {url}: Connection refused or host unreachable")
            except requests.exceptions.Timeout:
                self.errors[url] = f"Timed out after {self.timeout}s"
                console.print(f"[red][[FAIL]][/red] {url}: Timed out after {self.timeout}s")
            except requests.exceptions.RequestException as exc:
                self.errors[url] = str(exc)
                console.print(f"[red][[FAIL]][/red] {url}: {exc}")

        return results


def load_urls_from_file(path: Path) -> list[str]:
    """
    Read target URLs from a plain-text file, one URL per line.

    Skips blank lines and lines that start with '#'. Strips leading and
    trailing whitespace from each URL before returning.

    Args:
        path (Path): Path to the file containing URLs.

    Returns:
        list[str]: Non-empty, stripped URL strings from the file.

    Raises:
        FileNotFoundError: If the path does not exist (Click validates this
            earlier, but the function guards against direct calls too).
        ValueError: If the file contains no valid URLs after filtering.
    """
    if not path.exists():
        raise FileNotFoundError(f"URL file not found: {path}")

    urls = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        raise ValueError(f"No valid URLs found in {path}")

    return urls


def _build_results_dict(
    results: list[EndpointResult],
    errors: dict[str, str],
    scan_target: str,
) -> dict:
    """
    Serialise scan results into a JSON-compatible dict for report.json.

    Args:
        results (list[EndpointResult]): Completed endpoint analysis objects.
        errors (dict[str, str]): URL -> error message for failed requests.
        scan_target (str): Human-readable label for this scan session.

    Returns:
        dict: Fully serialisable dict containing metadata and per-endpoint data.
    """
    return {
        "scan_type": "active",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "sentry_version": __version__,
        "target": scan_target,
        "total_scanned": len(results),
        "total_errors": len(errors),
        "errors": errors,
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
    Render a single EndpointResult as a header findings table to con.

    Args:
        con (Console): The Rich Console to write output to.
        result (EndpointResult): Completed analysis for one URL.
    """
    grade_style = _GRADE_STYLES.get(result.grade, "white")
    con.print(f"\n[bold]--- {result.url} ---[/bold]")
    con.print(
        f"API Type: [cyan]{result.api_type}[/cyan]   "
        f"Score: [{grade_style}]{result.score}/100[/{grade_style}]   "
        f"Grade: [{grade_style}]{result.grade}[/{grade_style}]"
    )

    # Security header findings table
    con.print("\n[bold]Security Headers[/bold]")
    hdr_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    hdr_table.add_column("Header", min_width=30)
    hdr_table.add_column("Status", width=8)
    hdr_table.add_column("Severity", width=10)
    hdr_table.add_column("Detail")

    for f in result.findings:
        status_style = _STATUS_STYLES.get(f.status, "white")
        sev_style = _SEVERITY_STYLES.get(f.severity, "white")
        # Show the actual observed value when present, otherwise the rule description
        detail = f.actual_value if f.actual_value else f.description
        hdr_table.add_row(
            f.name,
            f"[{status_style}][{f.status}][/{status_style}]",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            detail,
        )

    con.print(hdr_table)

    # Authentication findings
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
    errors: dict[str, str],
    output_format: str,
    results_dict: Optional[dict] = None,
) -> None:
    """
    Print all scan results to target_console in the requested format.

    Args:
        target_console (Console): Rich Console to write to (may be a StringIO
            buffer console for report.txt capture).
        results (list[EndpointResult]): Completed endpoint analyses.
        errors (dict[str, str]): URL -> error string for failed requests.
        output_format (str): One of 'table', 'json', 'html', 'pdf'.
            html and pdf render as table to terminal; the file is saved by
            the caller after _render_results returns.
        results_dict (Optional[dict]): Pre-built results dict; used for JSON
            output to avoid rebuilding. Built from results if not provided.
    """
    if output_format == "json":
        data = results_dict or _build_results_dict(results, errors, "")
        target_console.print(json.dumps(data, indent=2, default=str))
        return

    target_console.print("\n[bold]Sentry -- Active Scan[/bold]")

    if not results and not errors:
        target_console.print("[yellow][[WARN]][/yellow] No URLs were scanned.")
        return

    for result in results:
        _render_endpoint(target_console, result)

    # Cross-URL summary
    if results:
        avg_score = sum(r.score for r in results) // len(results)
        fail_urls = sum(
            1 for r in results if any(f.status == "FAIL" for f in r.findings)
        )
        target_console.print("\n[bold]Summary[/bold]")
        target_console.print(
            f"  Scanned: [cyan]{len(results)}[/cyan] URL(s)   "
            f"Errors: [red]{len(errors)}[/red]   "
            f"Avg Score: {avg_score}/100"
        )
        if fail_urls:
            target_console.print(
                f"  [yellow][[!]][/yellow] {fail_urls} URL(s) have FAIL findings"
            )

    if errors:
        target_console.print("\n[bold]Failed URLs[/bold]")
        for url, reason in errors.items():
            target_console.print(f"  [red][[-]][/red] {url}: {reason}")


def run(config: dict) -> None:
    """
    Entry point for active-mode scans called by sentry/main.py.

    Resolves the URL list from config['url'] or config['file'], runs the
    ActiveScanner, renders results to the terminal in the requested format,
    and saves the report via core.reporter.save_report().

    Args:
        config (dict): Scan configuration dict from sentry/main.py._run(),
            containing keys: url, file, output, save, timeout,
            verify_ssl, verbose.
    """
    url: Optional[str] = config["url"]
    file: Optional[Path] = config["file"]
    output: str = config.get("output", "table")
    save_root: Optional[Path] = config.get("save")
    timeout: int = config.get("timeout", 30)
    verify_ssl: bool = config.get("verify_ssl", True)
    verbose: bool = config.get("verbose", False)

    # Resolve URL list and build the target label for the report directory
    if file is not None:
        urls = load_urls_from_file(file)
        scan_target = f"batch_{len(urls)}urls"
    else:
        # url is guaranteed non-None by main.py validation when file is None
        urls = [url]  # type: ignore[list-item]
        scan_target = url  # type: ignore[assignment]

    scanner = ActiveScanner(
        urls=urls,
        timeout=timeout,
        verify_ssl=verify_ssl,
        verbose=verbose,
        user_agent=config.get("user_agent"),
    )
    results = scanner.scan()

    # Build the structured dict once; reuse for both JSON terminal output and report.json
    results_dict = _build_results_dict(results, scanner.errors, scan_target)

    # Render to the live terminal
    _render_results(console, results, scanner.errors, output, results_dict)

    # Capture a plain-text mirror for report.txt (always table format)
    text_buf = io.StringIO()
    text_console = Console(file=text_buf, no_color=True, width=120)
    _render_results(text_console, results, scanner.errors, "table", results_dict)
    text_output = text_buf.getvalue()

    report_dir = save_report(
        target=scan_target,
        results=results_dict,
        text_output=text_output,
        save_root=save_root,
    )

    if output == "html":
        save_html_report(results_dict, report_dir)
    elif output == "pdf":
        save_pdf_report(results_dict, report_dir)
