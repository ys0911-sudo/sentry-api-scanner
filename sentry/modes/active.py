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
    normalize_url: Ensure a target URL has an explicit scheme (defaults to HTTPS).
    load_urls_from_file: Read and validate a URL list from a plain-text file.
    _build_results_dict: Serialise scan results into a JSON-compatible structure.
    _render_results: Print scan results to a Rich Console in the requested format.
    _render_endpoint: Print a single EndpointResult to a Rich Console.
"""

from __future__ import annotations

import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich import box
from rich.table import Table
from urllib3.util.retry import Retry

from sentry import __version__
from sentry.config.headers import AUTH_SECURITY_FLAGS
from sentry.core.analyzer import EndpointResult, analyze_headers
from sentry.core.detector import ApiType
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
    Orchestrates concurrent HTTP requests and header analysis for active mode.

    Each target URL is scanned independently: a GET captures the response
    headers, an OPTIONS preflight with a deliberately invalid probe Origin
    surfaces CORS misconfiguration, and — only for endpoints whose path already
    signals GraphQL or JSON-RPC — an optional read-only POST probe confirms the
    API type so body-signature detection works even though those protocols
    reject GET. URLs are processed across a thread pool; a per-URL failure is
    recorded in self.errors and never aborts the rest of the scan.

    Transient failures (connection resets, 429, 5xx) are retried with
    exponential backoff that honours any Retry-After header, so the scanner
    stays polite under rate limiting. POST probes are never retried — they are
    non-idempotent by nature, even though the probes used here are read-only.

    Attributes:
        urls (list[str]): Target URLs to scan (already scheme-normalised).
        timeout (int): Per-request timeout in seconds.
        verify_ssl (bool): Whether to verify TLS certificates.
        verbose (bool): When True, print each request URL as it is made.
        user_agent (str): User-Agent header sent with every request.
        concurrency (int): Maximum number of URLs scanned in parallel.
        retries (int): Retry attempts for transient connection/status failures.
        probe (bool): When True, send read-only POST probes to GraphQL/JSON-RPC
            paths to improve API type detection.
        errors (dict[str, str]): Maps URLs that failed to their error message.
            Populated by scan(); empty before the first call.

    Example:
        scanner = ActiveScanner(urls=["https://api.example.com"], concurrency=10)
        results = scanner.scan()
    """

    # Default User-Agent: identifies the tool without advertising "security scanner",
    # which can trigger WAF blocks and appear in target access logs.
    _DEFAULT_UA = f"sentryscan/{__version__}"

    # Deliberately invalid Origin: it can never be a legitimately whitelisted
    # value, so any reflection of it is a blind origin-reflection bug.
    _PROBE_ORIGIN = "https://sentry-probe.invalid"

    def __init__(
        self,
        urls: list[str],
        timeout: int = 30,
        verify_ssl: bool = True,
        verbose: bool = False,
        user_agent: Optional[str] = None,
        concurrency: int = 5,
        retries: int = 2,
        probe: bool = True,
    ) -> None:
        """
        Initialise the scanner with a target list and request options.

        Args:
            urls (list[str]): One or more target URLs (scheme-normalised).
            timeout (int): Per-request timeout in seconds.
            verify_ssl (bool): Verify TLS certificates when True.
            verbose (bool): Echo each request URL to the terminal when True.
            user_agent (Optional[str]): Override the HTTP User-Agent header.
                Defaults to a neutral string that does not advertise the tool
                as a security scanner to avoid WAF triggers and log noise.
            concurrency (int): Maximum URLs scanned in parallel (clamped to >=1).
            retries (int): Retry attempts for transient failures (clamped to >=0).
            probe (bool): Send read-only POST probes to GraphQL/JSON-RPC paths.
        """
        self.urls = urls
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.user_agent = user_agent or self._DEFAULT_UA
        self.concurrency = max(1, concurrency)
        self.retries = max(0, retries)
        self.probe = probe
        self.errors: dict[str, str] = {}
        # Console output is shared across worker threads; serialise writes so
        # progress and error lines do not interleave mid-line.
        self._print_lock = threading.Lock()

    def _emit(self, message: str) -> None:
        """
        Write a line to the shared console under a lock (thread-safe output).

        Args:
            message (str): Rich-markup message to print.
        """
        with self._print_lock:
            console.print(message)

    def _make_session(self) -> requests.Session:
        """
        Build a requests Session with retry/backoff mounted for both schemes.

        A fresh session per worker call keeps the scanner thread-safe (a single
        Session shared across threads is not guaranteed safe). Retries cover
        connection errors and the throttling/availability status codes; POST is
        intentionally excluded from the retry method set so probes are never
        replayed. Retry-After is respected for polite backoff under rate limits.

        Returns:
            requests.Session: Configured session ready for GET/OPTIONS/POST.
        """
        session = requests.Session()
        session.headers["User-Agent"] = self.user_agent
        retry = Retry(
            total=self.retries,
            connect=self.retries,
            read=self.retries,
            status=self.retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _post_probe(self, session: requests.Session, url: str) -> Optional[ApiType]:
        """
        Send a read-only POST probe when the path indicates GraphQL or JSON-RPC.

        These protocols reject GET, so their body signatures are unreachable in a
        GET-only scan. The probes are deliberately side-effect free: a GraphQL
        introspection query reads schema metadata only, and a JSON-RPC
        rpc.discover call uses the reserved 'rpc.' method namespace, which never
        maps to business operations. The probe is skipped for every other path,
        so the scanner never POSTs to, e.g., a REST collection that might create
        a resource.

        Args:
            session (requests.Session): Session to issue the probe on.
            url (str): Target URL whose path is inspected for protocol hints.

        Returns:
            Optional[ApiType]: ApiType.GRAPHQL or ApiType.JSONRPC when confirmed,
                               otherwise None (fall back to GET-based detection).
        """
        path = urlparse(url).path.lower()
        try:
            if "/graphql" in path or "/gql" in path:
                resp = session.post(
                    url,
                    json={"query": "{__schema{queryType{name}}}"},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
                body = resp.text[:2048] if resp.text else ""
                # A GraphQL endpoint answers introspection with a JSON envelope
                # containing data/errors, even when introspection is disabled.
                if "__schema" in body or '"data"' in body or '"errors"' in body:
                    if self.verbose:
                        self._emit(f"[cyan][[INFO]][/cyan] {url}: GraphQL confirmed via introspection probe")
                    return ApiType.GRAPHQL
            elif "/rpc" in path or "jsonrpc" in path or "json-rpc" in path or "json_rpc" in path:
                resp = session.post(
                    url,
                    json={"jsonrpc": "2.0", "method": "rpc.discover", "id": 1},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
                body = resp.text[:2048] if resp.text else ""
                if '"jsonrpc"' in body:
                    if self.verbose:
                        self._emit(f"[cyan][[INFO]][/cyan] {url}: JSON-RPC confirmed via discover probe")
                    return ApiType.JSONRPC
        except Exception:
            # Probe failures are non-fatal: detection simply falls back to the
            # GET response signals.
            pass
        return None

    def _scan_one(
        self, url: str
    ) -> tuple[str, Optional[EndpointResult], Optional[str]]:
        """
        Scan a single URL and return its analysis result or an error string.

        Runs the GET request, the CORS OPTIONS preflight, and the optional POST
        probe, then analyses the response. Designed to run inside a worker
        thread: it returns its own result/error tuple rather than mutating shared
        state, so the caller can aggregate from the main thread without locking.

        Args:
            url (str): Target URL to scan.

        Returns:
            tuple[str, Optional[EndpointResult], Optional[str]]:
                (url, result, None) on success, or (url, None, error) on failure.
        """
        if self.verbose:
            self._emit(f"[cyan][[INFO]][/cyan] Requesting: {url}")

        session = self._make_session()
        try:
            response = session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
        except requests.exceptions.SSLError as exc:
            self._emit(
                f"[red][[FAIL]][/red] {url}: SSL certificate error "
                "(try --insecure to skip verification)"
            )
            return url, None, f"SSL error: {exc}"
        except requests.exceptions.ConnectionError:
            self._emit(f"[red][[FAIL]][/red] {url}: Connection refused or host unreachable")
            return url, None, "Connection refused or host unreachable"
        except requests.exceptions.Timeout:
            self._emit(f"[red][[FAIL]][/red] {url}: Timed out after {self.timeout}s")
            return url, None, f"Timed out after {self.timeout}s"
        except requests.exceptions.RequestException as exc:
            self._emit(f"[red][[FAIL]][/red] {url}: {exc}")
            return url, None, str(exc)

        body_sample = response.text[:2048] if response.text else None
        merged_headers = dict(response.headers)
        probe_request_headers: dict[str, str] = {}

        # OPTIONS preflight with the invalid probe Origin to surface CORS issues.
        try:
            options_resp = session.options(
                url,
                headers={
                    "Origin": self._PROBE_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization, Content-Type",
                },
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            # Merge only CORS-relevant headers so they reach _analyze_cors()
            # without overwriting the GET response's other headers.
            for k, v in options_resp.headers.items():
                kl = k.lower()
                if kl.startswith("access-control") or kl == "vary":
                    merged_headers[k] = v
            probe_request_headers = {"origin": self._PROBE_ORIGIN}
        except Exception:
            pass

        # Optional read-only POST probe to confirm GraphQL / JSON-RPC type when
        # the path indicates one. An explicit type override beats GET-only
        # detection, which cannot see those protocols' request/response bodies.
        api_type_override = self._post_probe(session, url) if self.probe else None

        result = analyze_headers(
            url=url,
            response_headers=merged_headers,
            api_type=api_type_override,
            body_sample=body_sample,
            status_code=response.status_code,
            request_headers=probe_request_headers or None,
        )
        return url, result, None

    def scan(self) -> list[EndpointResult]:
        """
        Execute the active scan across all target URLs using a thread pool.

        Each URL is scanned by _scan_one() in a worker thread. Failures are
        collected into self.errors. Results are returned in the original input
        order regardless of completion order.

        Returns:
            list[EndpointResult]: One result per successfully scanned URL, in
                the same order as self.urls (minus errored entries).

        Raises:
            Nothing — all request-level errors are captured in self.errors.
        """
        # The user explicitly opted in to skipping verification; suppress the
        # urllib3 warning that would otherwise fire on every request.
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        results_by_url: dict[str, EndpointResult] = {}
        # self.errors and results_by_url are written only here, on the main
        # thread, as each future completes — no locking needed for them.
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {executor.submit(self._scan_one, u): u for u in self.urls}
            for future in as_completed(futures):
                url, result, error = future.result()
                if error is not None:
                    self.errors[url] = error
                elif result is not None:
                    results_by_url[url] = result

        return [results_by_url[u] for u in self.urls if u in results_by_url]


def normalize_url(url: str) -> str:
    """
    Ensure a target URL carries an explicit scheme, defaulting to HTTPS.

    Users frequently supply bare hosts ("api.example.com/v1"). Without a scheme
    requests raises MissingSchema and the target is silently lost. When no
    "://" separator is present, https:// is prepended — HTTPS is the safe
    default and the transport-security checks assume an encrypted origin.

    Args:
        url (str): Raw URL or bare host string.

    Returns:
        str: A URL guaranteed to start with a scheme (unchanged if it already
             had one). Empty input is returned unchanged.
    """
    url = url.strip()
    if url and "://" not in url:
        return "https://" + url
    return url


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
        normalize_url(line.strip())
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
            verify_ssl, verbose, concurrency, retries, probe.
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
        # url is guaranteed non-None by main.py validation when file is None.
        # Normalise the scheme so a bare host ("api.example.com") still scans.
        urls = [normalize_url(url)]  # type: ignore[arg-type]
        scan_target = urls[0]

    scanner = ActiveScanner(
        urls=urls,
        timeout=timeout,
        verify_ssl=verify_ssl,
        verbose=verbose,
        user_agent=config.get("user_agent"),
        concurrency=config.get("concurrency", 5),
        retries=config.get("retries", 2),
        probe=config.get("probe", True),
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
