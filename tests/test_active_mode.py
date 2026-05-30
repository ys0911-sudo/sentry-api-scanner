"""
test_active_mode.py

Tests for sentry.modes.active. Covers the four public symbols and the
run() integration path:

  - load_urls_from_file: blank/comment filtering, error cases
  - ActiveScanner.scan: happy path, per-URL error handling, scan continuation
  - _build_results_dict: output structure and JSON serialisability
  - _render_results: table/JSON/fallback formats, crash-free guarantee
  - run: single-URL and file-input paths, report file creation

HTTP fixture responses are served by pytest-httpserver; no real network calls
are made. Request-level errors (timeout, SSL, connection) are injected via
unittest.mock. Report files are written to pytest's tmp_path fixture so tests
do not pollute ~/sentry-reports/.

Functions:
    _make_console: Return a no-color Console backed by a StringIO buffer.
    _minimal_result: Build a minimal EndpointResult for rendering tests.
    TestLoadUrlsFromFile.*: load_urls_from_file tests.
    TestActiveScannerScan.*: ActiveScanner.scan tests.
    TestBuildResultsDict.*: _build_results_dict tests.
    TestRenderResults.*: _render_results tests.
    TestRun.*: run() integration tests.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentry.core.analyzer import EndpointResult, HeaderFinding
from sentry.modes.active import (
    ActiveScanner,
    _build_results_dict,
    _render_results,
    load_urls_from_file,
    run,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_console() -> tuple[Console, io.StringIO]:
    """
    Return a no-color Rich Console writing to a StringIO buffer.

    Returns:
        tuple[Console, StringIO]: Console and the buffer it writes to.
    """
    buf = io.StringIO()
    con = Console(file=buf, no_color=True, width=120)
    return con, buf


def _minimal_result(
    url: str = "https://api.example.com",
    score: int = 50,
    grade: str = "C",
) -> EndpointResult:
    """
    Build a minimal EndpointResult with one FAIL finding for use in tests.

    Args:
        url (str): URL to attach to the result.
        score (int): Numeric security score.
        grade (str): Letter grade.

    Returns:
        EndpointResult: A fully-constructed but minimal result object.
    """
    return EndpointResult(
        url=url,
        score=score,
        grade=grade,
        api_type="rest",
        findings=[
            HeaderFinding(
                name="Strict-Transport-Security",
                status="FAIL",
                severity="HIGH",
                description="Forces HTTPS; missing allows downgrade attacks",
                recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                actual_value=None,
            )
        ],
        auth_findings=[],
        raw_headers={"content-type": "application/json"},
    )


def _mock_response(
    headers: dict | None = None,
    text: str = "{}",
    status_code: int = 200,
) -> MagicMock:
    """
    Build a MagicMock that mimics a requests.Response for scanner injection.

    Args:
        headers (dict): HTTP response headers.
        text (str): Response body text.
        status_code (int): HTTP status code.

    Returns:
        MagicMock: Response-like mock accepted by ActiveScanner.scan().
    """
    resp = MagicMock()
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = text
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------
# load_urls_from_file
# ---------------------------------------------------------------------------

class TestLoadUrlsFromFile:
    """Tests for load_urls_from_file."""

    def test_reads_valid_urls(self, tmp_path: Path) -> None:
        """Valid two-line file returns both URLs."""
        f = tmp_path / "urls.txt"
        f.write_text("https://example.com\nhttps://api.example.com\n")
        assert load_urls_from_file(f) == ["https://example.com", "https://api.example.com"]

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        """Blank lines between URLs are silently dropped."""
        f = tmp_path / "urls.txt"
        f.write_text("\nhttps://example.com\n\nhttps://api.example.com\n\n")
        assert load_urls_from_file(f) == ["https://example.com", "https://api.example.com"]

    def test_skips_comment_lines(self, tmp_path: Path) -> None:
        """Lines starting with # are silently dropped."""
        f = tmp_path / "urls.txt"
        f.write_text("# target 1\nhttps://example.com\n# target 2\nhttps://api.example.com\n")
        assert load_urls_from_file(f) == ["https://example.com", "https://api.example.com"]

    def test_strips_leading_and_trailing_whitespace(self, tmp_path: Path) -> None:
        """URLs with surrounding whitespace are returned stripped."""
        f = tmp_path / "urls.txt"
        f.write_text("  https://example.com  \n\thttps://api.example.com\t\n")
        assert load_urls_from_file(f) == ["https://example.com", "https://api.example.com"]

    def test_empty_file_raises_value_error(self, tmp_path: Path) -> None:
        """A completely empty file raises ValueError."""
        f = tmp_path / "urls.txt"
        f.write_text("")
        with pytest.raises(ValueError, match="No valid URLs"):
            load_urls_from_file(f)

    def test_all_comments_raises_value_error(self, tmp_path: Path) -> None:
        """A file containing only comment lines raises ValueError."""
        f = tmp_path / "urls.txt"
        f.write_text("# comment one\n# comment two\n")
        with pytest.raises(ValueError, match="No valid URLs"):
            load_urls_from_file(f)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        """A path that does not exist raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_urls_from_file(tmp_path / "does_not_exist.txt")

    def test_single_url_no_trailing_newline(self, tmp_path: Path) -> None:
        """Single URL without trailing newline is returned correctly."""
        f = tmp_path / "urls.txt"
        f.write_text("https://example.com")
        assert load_urls_from_file(f) == ["https://example.com"]


# ---------------------------------------------------------------------------
# ActiveScanner.scan
# ---------------------------------------------------------------------------

class TestActiveScannerScan:
    """Tests for ActiveScanner.scan()."""

    def test_single_url_returns_one_result(self, httpserver) -> None:
        """One URL produces exactly one EndpointResult with no errors."""
        httpserver.expect_request("/api").respond_with_data(
            '{"data": []}',
            headers={"Content-Type": "application/json"},
            status=200,
        )
        scanner = ActiveScanner(urls=[httpserver.url_for("/api")], timeout=5)
        results = scanner.scan()
        assert len(results) == 1
        assert results[0].url == httpserver.url_for("/api")
        assert scanner.errors == {}

    def test_result_carries_expected_fields(self, httpserver) -> None:
        """Returned EndpointResult has score, grade, api_type, and findings."""
        httpserver.expect_request("/api").respond_with_data(
            '{"ok": true}',
            headers={"Content-Type": "application/json", "X-Content-Type-Options": "nosniff"},
            status=200,
        )
        scanner = ActiveScanner(urls=[httpserver.url_for("/api")], timeout=5)
        result = scanner.scan()[0]
        assert isinstance(result.score, int)
        assert result.grade in ("A", "B", "C", "D", "F")
        assert result.api_type != ""
        assert isinstance(result.findings, list)

    def test_present_security_headers_produce_pass_findings(self, httpserver) -> None:
        """Headers present in the response appear as PASS findings."""
        httpserver.expect_request("/api").respond_with_data(
            "",
            headers={
                "Content-Type": "application/json",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
            status=200,
        )
        scanner = ActiveScanner(urls=[httpserver.url_for("/api")], timeout=5)
        result = scanner.scan()[0]
        by_name = {f.name: f.status for f in result.findings}
        assert by_name.get("Strict-Transport-Security") == "PASS"
        assert by_name.get("X-Content-Type-Options") == "PASS"

    def test_connection_error_recorded_scan_continues(self) -> None:
        """ConnectionError is captured in errors; result list stays empty."""
        scanner = ActiveScanner(urls=["https://api.example.com"], timeout=5)
        with patch.object(
            requests.Session, "get",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            results = scanner.scan()
        assert results == []
        assert "https://api.example.com" in scanner.errors

    def test_timeout_error_message_contains_seconds(self) -> None:
        """Timeout error message includes the configured timeout duration."""
        scanner = ActiveScanner(urls=["https://api.example.com"], timeout=7)
        with patch.object(
            requests.Session, "get",
            side_effect=requests.exceptions.Timeout(),
        ):
            scanner.scan()
        assert "7" in scanner.errors["https://api.example.com"]

    def test_ssl_error_recorded(self) -> None:
        """SSLError is captured in errors with 'SSL' in the message."""
        scanner = ActiveScanner(urls=["https://api.example.com"], timeout=5)
        with patch.object(
            requests.Session, "get",
            side_effect=requests.exceptions.SSLError("cert verify failed"),
        ):
            scanner.scan()
        assert "SSL" in scanner.errors["https://api.example.com"]

    def test_scan_continues_after_per_url_error(self, httpserver) -> None:
        """A failing URL does not abort the scan; subsequent URLs are processed."""
        httpserver.expect_request("/good").respond_with_data(
            '{"ok": true}',
            headers={"Content-Type": "application/json"},
            status=200,
        )
        good_url = httpserver.url_for("/good")
        bad_url = "https://unreachable.example.com/bad"

        call_num = 0

        def mock_get(self_s, url, **kwargs):
            nonlocal call_num
            call_num += 1
            if call_num == 1:
                raise requests.exceptions.ConnectionError()
            # Call the real requests for the second (good) URL
            return requests.Session.get.__wrapped__(self_s, url, **kwargs)  # type: ignore[attr-defined]

        # Use a real session for the good URL by delegating back to requests
        good_resp = _mock_response()
        responses_list = [
            requests.exceptions.ConnectionError(),
            good_resp,
        ]

        with patch.object(requests.Session, "get", side_effect=responses_list):
            scanner = ActiveScanner(urls=[bad_url, good_url], timeout=5)
            results = scanner.scan()

        assert len(results) == 1
        assert bad_url in scanner.errors
        # The good URL still produced a result
        assert results[0].url == good_url

    def test_http_4xx_still_produces_result(self, httpserver) -> None:
        """A 404 response is analysed normally; it is not treated as an error."""
        httpserver.expect_request("/missing").respond_with_data(
            '{"error": "not found"}',
            headers={"Content-Type": "application/json"},
            status=404,
        )
        scanner = ActiveScanner(urls=[httpserver.url_for("/missing")], timeout=5)
        results = scanner.scan()
        assert len(results) == 1
        assert scanner.errors == {}

    def test_multiple_urls_return_multiple_results(self, httpserver) -> None:
        """Three URLs produce three results in the same order."""
        for path in ("/a", "/b", "/c"):
            httpserver.expect_request(path).respond_with_data(
                "{}",
                headers={"Content-Type": "application/json"},
                status=200,
            )
        urls = [httpserver.url_for(p) for p in ("/a", "/b", "/c")]
        scanner = ActiveScanner(urls=urls, timeout=5)
        results = scanner.scan()
        assert len(results) == 3
        assert [r.url for r in results] == urls

    def test_verbose_true_does_not_crash(self, httpserver) -> None:
        """verbose=True prints the URL but does not affect the result."""
        httpserver.expect_request("/api").respond_with_data(
            "{}",
            headers={"Content-Type": "application/json"},
            status=200,
        )
        scanner = ActiveScanner(
            urls=[httpserver.url_for("/api")], timeout=5, verbose=True
        )
        assert len(scanner.scan()) == 1

    def test_verify_ssl_false_is_forwarded_to_requests(self) -> None:
        """verify_ssl=False is passed through as verify=False to requests.get."""
        good_resp = _mock_response()
        with patch.object(requests.Session, "get", return_value=good_resp) as mock_get:
            scanner = ActiveScanner(
                urls=["https://api.example.com"], verify_ssl=False
            )
            scanner.scan()
        _, kwargs = mock_get.call_args
        assert kwargs.get("verify") is False

    def test_user_agent_header_set(self) -> None:
        """The Scanner sets a Sentry user-agent on the session."""
        good_resp = _mock_response()
        with patch.object(requests.Session, "get", return_value=good_resp):
            scanner = ActiveScanner(urls=["https://api.example.com"])
            scanner.scan()
        # inspect the session directly
        session = requests.Session()
        # We cannot inspect the already-used session, but we verify the scanner
        # constructs one with the right header by patching Session.__init__
        captured: dict = {}

        real_init = requests.Session.__init__

        def patched_init(self_s, *a, **kw):
            real_init(self_s, *a, **kw)
            captured["session"] = self_s

        with patch.object(requests.Session, "__init__", patched_init):
            with patch.object(requests.Session, "get", return_value=good_resp):
                scanner2 = ActiveScanner(urls=["https://api.example.com"])
                scanner2.scan()

        assert "Sentry/" in captured["session"].headers.get("User-Agent", "")


# ---------------------------------------------------------------------------
# _build_results_dict
# ---------------------------------------------------------------------------

class TestBuildResultsDict:
    """Tests for _build_results_dict."""

    def test_top_level_keys_present(self) -> None:
        """All expected top-level keys are in the returned dict."""
        d = _build_results_dict([_minimal_result()], {}, "api.example.com")
        expected_keys = {
            "scan_type", "timestamp", "sentry_version", "target",
            "total_scanned", "total_errors", "errors", "results",
        }
        assert expected_keys.issubset(d.keys())

    def test_scan_type_is_active(self) -> None:
        """scan_type is always 'active'."""
        assert _build_results_dict([], {}, "x")["scan_type"] == "active"

    def test_total_scanned_and_errors_counts(self) -> None:
        """total_scanned and total_errors reflect the input sizes."""
        results = [_minimal_result("https://a.com"), _minimal_result("https://b.com")]
        errors = {"https://c.com": "timed out"}
        d = _build_results_dict(results, errors, "batch")
        assert d["total_scanned"] == 2
        assert d["total_errors"] == 1

    def test_result_entry_keys(self) -> None:
        """Each entry in results[] contains all required keys."""
        d = _build_results_dict([_minimal_result()], {}, "target")
        entry = d["results"][0]
        for key in ("url", "score", "grade", "api_type", "findings", "auth_findings", "raw_headers"):
            assert key in entry, f"Missing key in result entry: {key}"

    def test_finding_entry_keys(self) -> None:
        """Each entry in findings[] contains all required keys."""
        d = _build_results_dict([_minimal_result()], {}, "target")
        finding = d["results"][0]["findings"][0]
        for key in ("name", "status", "severity", "description", "recommendation", "actual_value"):
            assert key in finding, f"Missing key in finding entry: {key}"

    def test_empty_results_and_errors(self) -> None:
        """Empty inputs produce a valid dict with zero counts and empty lists."""
        d = _build_results_dict([], {}, "empty")
        assert d["results"] == []
        assert d["errors"] == {}
        assert d["total_scanned"] == 0
        assert d["total_errors"] == 0

    def test_is_json_serialisable(self) -> None:
        """The returned dict round-trips through json.dumps / json.loads."""
        result = _minimal_result()
        d = _build_results_dict([result], {"https://x.com": "err"}, "target")
        parsed = json.loads(json.dumps(d, default=str))
        assert parsed["scan_type"] == "active"
        assert parsed["total_scanned"] == 1
        assert parsed["total_errors"] == 1

    def test_target_label_preserved(self) -> None:
        """The scan_target string is stored verbatim in 'target'."""
        d = _build_results_dict([], {}, "batch_5urls")
        assert d["target"] == "batch_5urls"


# ---------------------------------------------------------------------------
# _render_results
# ---------------------------------------------------------------------------

class TestRenderResults:
    """Tests for _render_results."""

    def test_table_format_produces_output(self) -> None:
        """Table format writes content to the Console."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result()], {}, "table")
        assert len(buf.getvalue()) > 0

    def test_table_contains_fail_tag(self) -> None:
        """A FAIL finding produces a [FAIL] tag in the table output."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result()], {}, "table")
        assert "[FAIL]" in buf.getvalue()

    def test_table_contains_target_url(self) -> None:
        """The scanned URL appears in the table output."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result(url="https://target.example.com")], {}, "table")
        assert "target.example.com" in buf.getvalue()

    def test_table_contains_header_name(self) -> None:
        """The header rule name (e.g. Strict-Transport-Security) appears in output."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result()], {}, "table")
        assert "Strict-Transport-Security" in buf.getvalue()

    def test_json_format_produces_valid_json(self) -> None:
        """JSON format writes parseable JSON containing scan_type."""
        con, buf = _make_console()
        d = _build_results_dict([_minimal_result()], {}, "target")
        _render_results(con, [_minimal_result()], {}, "json", results_dict=d)
        parsed = json.loads(buf.getvalue())
        assert parsed["scan_type"] == "active"

    def test_html_falls_back_to_table_with_info_note(self) -> None:
        """html format prints an [INFO] fallback note then renders table content."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result()], {}, "html")
        output = buf.getvalue()
        assert "HTML" in output
        # Table content still rendered after the note
        assert "[FAIL]" in output or "Sentry" in output

    def test_pdf_falls_back_to_table_with_info_note(self) -> None:
        """pdf format prints an [INFO] fallback note then renders table content."""
        con, buf = _make_console()
        _render_results(con, [_minimal_result()], {}, "pdf")
        assert "PDF" in buf.getvalue()

    def test_empty_results_no_urls_prints_warning(self) -> None:
        """No results and no errors produces the 'No URLs were scanned' warning."""
        con, buf = _make_console()
        _render_results(con, [], {}, "table")
        assert "No URLs were scanned" in buf.getvalue()

    def test_errors_appear_in_output(self) -> None:
        """Failed URLs and their error messages appear in the output."""
        con, buf = _make_console()
        _render_results(con, [], {"https://fail.example.com": "Connection refused"}, "table")
        assert "fail.example.com" in buf.getvalue()

    def test_summary_shows_scanned_count(self) -> None:
        """Summary line shows the number of successfully scanned URLs."""
        con, buf = _make_console()
        results = [_minimal_result("https://a.com"), _minimal_result("https://b.com")]
        _render_results(con, results, {}, "table")
        assert "2" in buf.getvalue()

    def test_multiple_results_all_urls_appear(self) -> None:
        """All URLs in the results list appear in the table output."""
        con, buf = _make_console()
        results = [
            _minimal_result("https://first.example.com"),
            _minimal_result("https://second.example.com"),
        ]
        _render_results(con, results, {}, "table")
        output = buf.getvalue()
        assert "first.example.com" in output
        assert "second.example.com" in output


# ---------------------------------------------------------------------------
# run() — integration
# ---------------------------------------------------------------------------

class TestRun:
    """Integration tests for the run() entry point."""

    def test_single_url_creates_report_json_and_txt(self, httpserver, tmp_path: Path) -> None:
        """run() with a single URL creates both report.json and report.txt."""
        httpserver.expect_request("/api").respond_with_data(
            '{"data": []}',
            headers={"Content-Type": "application/json"},
            status=200,
        )
        run({
            "url": httpserver.url_for("/api"),
            "file": None,
            "output": "table",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(subdirs) == 1
        assert (subdirs[0] / "report.json").exists()
        assert (subdirs[0] / "report.txt").exists()

    def test_single_url_report_json_structure(self, httpserver, tmp_path: Path) -> None:
        """report.json contains scan_type, total_scanned, and one result entry."""
        httpserver.expect_request("/v1/users").respond_with_data(
            '{"users": []}',
            headers={"Content-Type": "application/json"},
            status=200,
        )
        run({
            "url": httpserver.url_for("/v1/users"),
            "file": None,
            "output": "table",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        report_dir = next(tmp_path.iterdir())
        data = json.loads((report_dir / "report.json").read_text())
        assert data["scan_type"] == "active"
        assert data["total_scanned"] == 1
        assert len(data["results"]) == 1

    def test_file_input_creates_batch_report(self, httpserver, tmp_path: Path) -> None:
        """run() with --file scans all URLs and labels the target batch_Nurls."""
        for path in ("/e1", "/e2"):
            httpserver.expect_request(path).respond_with_data(
                "{}", headers={"Content-Type": "application/json"}, status=200
            )
        url_file = tmp_path / "urls.txt"
        url_file.write_text(
            httpserver.url_for("/e1") + "\n" + httpserver.url_for("/e2") + "\n"
        )
        run({
            "url": None,
            "file": url_file,
            "output": "table",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(subdirs) == 1
        data = json.loads((subdirs[0] / "report.json").read_text())
        assert data["total_scanned"] == 2
        assert "batch_2urls" in data["target"]

    def test_all_errors_still_saves_report(self, tmp_path: Path) -> None:
        """run() saves a valid report.json even when every URL fails."""
        with patch.object(
            requests.Session, "get",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            run({
                "url": "https://api.example.com",
                "file": None,
                "output": "table",
                "save": tmp_path,
                "timeout": 1,
                "verify_ssl": True,
                "verbose": False,
            })
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(subdirs) == 1
        data = json.loads((subdirs[0] / "report.json").read_text())
        assert data["total_scanned"] == 0
        assert data["total_errors"] == 1

    def test_json_output_still_saves_report_files(self, httpserver, tmp_path: Path) -> None:
        """--output json renders JSON to terminal but still writes both report files."""
        httpserver.expect_request("/api").respond_with_data(
            "{}", headers={"Content-Type": "application/json"}, status=200
        )
        run({
            "url": httpserver.url_for("/api"),
            "file": None,
            "output": "json",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(subdirs) == 1
        assert (subdirs[0] / "report.json").exists()
        assert (subdirs[0] / "report.txt").exists()

    def test_report_txt_is_plain_text(self, httpserver, tmp_path: Path) -> None:
        """report.txt contains plain text with no Rich markup codes."""
        httpserver.expect_request("/api").respond_with_data(
            "{}", headers={"Content-Type": "application/json"}, status=200
        )
        run({
            "url": httpserver.url_for("/api"),
            "file": None,
            "output": "table",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        report_dir = next(tmp_path.iterdir())
        txt = (report_dir / "report.txt").read_text()
        # Rich markup uses [bold], [green] etc. — none should appear in plain text
        assert "[bold]" not in txt
        assert "[green]" not in txt

    def test_file_input_comments_excluded_from_count(self, httpserver, tmp_path: Path) -> None:
        """Comment and blank lines in the URL file do not inflate the batch count."""
        httpserver.expect_request("/only").respond_with_data(
            "{}", headers={"Content-Type": "application/json"}, status=200
        )
        url_file = tmp_path / "urls.txt"
        url_file.write_text(
            "# this is a comment\n"
            + httpserver.url_for("/only")
            + "\n\n"
        )
        run({
            "url": None,
            "file": url_file,
            "output": "table",
            "save": tmp_path,
            "timeout": 5,
            "verify_ssl": True,
            "verbose": False,
        })
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        data = json.loads((subdirs[0] / "report.json").read_text())
        assert data["total_scanned"] == 1
        assert "batch_1urls" in data["target"]
