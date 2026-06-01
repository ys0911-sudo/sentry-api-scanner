"""
tests/test_analyzer_regressions.py

Regression tests for correctness bugs fixed in the analyzer and reporter.

Covers:
  - Set-Cookie parsing: a comma inside the Expires=<HTTP-date> attribute must
    not fragment a single cookie into phantom missing-flag findings, and folded
    multi-cookie values must still be split on real cookie boundaries.
  - CORS: cors_missing_vary_origin must not fire for a static wildcard origin
    (Vary: Origin is meaningless there) but must still fire for a dynamic origin.
  - Reporter: the HTML report must HTML-escape the errors section so a malicious
    target URL or server error string cannot inject markup/script.
"""

from __future__ import annotations

from sentry.core.analyzer import (
    _analyze_cors,
    _check_cookies,
    _looks_like_secret,
    analyze_headers,
)
from sentry.core.reporter import render_html


def _apikey_url_findings(url: str):
    """Return apikey AuthFindings produced for a URL with empty response headers."""
    result = analyze_headers(url=url, response_headers={})
    return [af for af in result.auth_findings if af.auth_type == "apikey"]


# ---------------------------------------------------------------------------
# Set-Cookie parsing
# ---------------------------------------------------------------------------

class TestSetCookieParsing:
    """Set-Cookie values must be split on cookie boundaries, not date commas."""

    def test_secure_cookie_with_expires_comma_has_no_flags(self) -> None:
        # The comma in 'Expires=Wed, 21 Oct ...' previously split this single
        # secure cookie into fragments, producing three false missing-flag findings.
        headers = {
            "set-cookie": (
                "sessionid=abc123; Path=/; "
                "Expires=Wed, 21 Oct 2025 07:28:00 GMT; "
                "Secure; HttpOnly; SameSite=Strict"
            )
        }
        findings = _check_cookies(headers)
        assert len(findings) == 1
        assert findings[0].auth_type == "session"
        assert findings[0].flags == []

    def test_insecure_cookie_flags_all_three_attributes(self) -> None:
        findings = _check_cookies({"set-cookie": "sessionid=abc; Path=/"})
        assert len(findings) == 1
        assert set(findings[0].flags) == {
            "cookie_missing_secure",
            "cookie_missing_httponly",
            "cookie_missing_samesite",
        }

    def test_folded_multi_cookie_splits_on_boundary(self) -> None:
        # Two cookies folded into one comma-joined value (as requests presents
        # them). Only the session cookie is reported, and it is the insecure one.
        headers = {"set-cookie": "csrftoken=xyz; Secure, JSESSIONID=qqq; Path=/"}
        findings = _check_cookies(headers)
        assert len(findings) == 1
        assert findings[0].auth_type == "session"
        assert "cookie_missing_secure" in findings[0].flags

    def test_non_session_cookie_is_ignored(self) -> None:
        assert _check_cookies({"set-cookie": "theme=dark; Path=/"}) == []


# ---------------------------------------------------------------------------
# CORS Vary: Origin
# ---------------------------------------------------------------------------

class TestCorsVaryOrigin:
    """Vary: Origin is only meaningful when the allowed origin is dynamic."""

    def test_wildcard_origin_does_not_flag_missing_vary(self) -> None:
        flags = [f for af in _analyze_cors({"access-control-allow-origin": "*"}, {})
                 for f in af.flags]
        assert "cors_wildcard_origin" in flags
        assert "cors_missing_vary_origin" not in flags

    def test_reflected_origin_without_vary_flags_missing_vary(self) -> None:
        resp = {"access-control-allow-origin": "https://app.example.com"}
        req = {"origin": "https://app.example.com"}
        flags = [f for af in _analyze_cors(resp, req) for f in af.flags]
        assert "cors_reflected_origin" in flags
        assert "cors_missing_vary_origin" in flags


# ---------------------------------------------------------------------------
# Reporter HTML escaping
# ---------------------------------------------------------------------------

class TestHtmlErrorEscaping:
    """The errors section must escape user/server-controlled strings."""

    def test_errors_section_escapes_markup(self) -> None:
        results_dict = {
            "scan_type": "active",
            "sentry_version": "0.1.0",
            "target": "x",
            "results": [],
            "errors": {
                "https://evil/<script>alert(1)</script>": "boom <img src=x onerror=alert(2)>",
            },
        }
        out = render_html(results_dict)
        assert "<script>alert(1)</script>" not in out
        assert "<img src=x onerror=alert(2)>" not in out
        assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# End-to-end: cookie analysis through analyze_headers
# ---------------------------------------------------------------------------

class TestApiKeyUrlPrecision:
    """Generic URL params must not flag non-secret values; strong names always do."""

    def test_generic_param_with_plain_word_is_not_flagged(self) -> None:
        assert _apikey_url_findings("https://api.example.com/items?key=name") == []

    def test_generic_param_with_small_int_is_not_flagged(self) -> None:
        assert _apikey_url_findings("https://api.example.com/items?token=1") == []

    def test_generic_param_with_boolean_is_not_flagged(self) -> None:
        assert _apikey_url_findings("https://api.example.com/items?auth=true") == []

    def test_client_id_is_not_flagged_as_secret(self) -> None:
        # An OAuth client_id is a public identifier by design.
        assert _apikey_url_findings(
            "https://api.example.com/oauth/authorize?client_id=myapp"
        ) == []

    def test_generic_param_with_secret_value_is_flagged(self) -> None:
        findings = _apikey_url_findings(
            "https://api.example.com/items?key=AKIAIOSFODNN7EXAMPLE"
        )
        assert len(findings) == 1
        assert "apikey_in_url" in findings[0].flags

    def test_strong_param_always_flagged_regardless_of_value(self) -> None:
        findings = _apikey_url_findings("https://api.example.com/items?api_key=x")
        assert len(findings) == 1
        assert "apikey_in_url" in findings[0].flags

    def test_apikey_in_url_over_http_adds_transport_flag(self) -> None:
        findings = _apikey_url_findings("http://api.example.com/items?api_key=x")
        assert findings and set(findings[0].flags) == {"apikey_in_url", "apikey_over_http"}

    def test_bare_token_request_header_no_longer_detected(self) -> None:
        result = analyze_headers(
            url="https://api.example.com",
            response_headers={},
            request_headers={"token": "abc"},
        )
        assert [af for af in result.auth_findings if af.auth_type == "apikey"] == []

    def test_named_api_key_request_header_still_detected(self) -> None:
        result = analyze_headers(
            url="https://api.example.com",
            response_headers={},
            request_headers={"x-api-key": "abc"},
        )
        assert any(af.auth_type == "apikey" for af in result.auth_findings)


class TestLooksLikeSecret:
    """Unit coverage for the URL-parameter secret heuristic."""

    def test_short_value_is_not_secret(self) -> None:
        assert _looks_like_secret("a1b2") is False

    def test_plain_word_is_not_secret(self) -> None:
        assert _looks_like_secret("username") is False

    def test_boolean_is_not_secret(self) -> None:
        assert _looks_like_secret("true") is False

    def test_mixed_alnum_is_secret(self) -> None:
        assert _looks_like_secret("AKIAIOSFODNN7EXAMPLE") is True

    def test_long_hex_digest_is_secret(self) -> None:
        assert _looks_like_secret("0123456789abcdef0123456789abcdef") is True


class TestAnalyzeHeadersCookies:
    """A secure session cookie must not lower the auth posture via false flags."""

    def test_secure_cookie_produces_clean_session_finding(self) -> None:
        result = analyze_headers(
            url="https://api.example.com/login",
            response_headers={
                "set-cookie": (
                    "sessionid=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT; "
                    "Secure; HttpOnly; SameSite=Lax"
                ),
            },
        )
        session_findings = [af for af in result.auth_findings if af.auth_type == "session"]
        assert len(session_findings) == 1
        assert session_findings[0].flags == []
