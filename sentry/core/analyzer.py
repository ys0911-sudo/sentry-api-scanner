"""
analyzer.py

Evaluates HTTP response headers against the security rules in
sentry/config/headers.py and produces a fully scored EndpointResult for every
scanned URL. The analyzer is mode-agnostic: active and passive both call
analyze_headers() with whatever headers they captured.

Two evaluation passes run for each endpoint:

  1. Security header analysis — every rule in RECOMMENDED_HEADERS is checked
     for presence and value quality (PASS / WARN / FAIL). Every rule in
     HARMFUL_HEADERS is checked for absence (PASS if absent, FAIL if present).
     Headers excluded for the detected API type are silently skipped.

  2. Authentication detection — request headers, response headers, URL
     parameters, and Set-Cookie headers are inspected for authentication
     mechanism signals. Detected mechanisms are checked against the
     AUTH_SECURITY_FLAGS table and any misconfigurations are reported as
     AuthFinding objects attached to the EndpointResult.

Scoring starts at 100. Points are deducted for missing recommended headers
(weighted by severity) and for each harmful header present. The final integer
score maps to a letter grade A–F.

Classes:
    HeaderFinding: Analysis result for a single header rule.
    AuthFinding: Detection result for one authentication mechanism.
    EndpointResult: Aggregated analysis output for one scanned URL.

Functions:
    analyze_headers: Run both analysis passes and return an EndpointResult.
    score_to_grade: Convert a 0–100 score to a letter grade string.
    _evaluate_header_quality: Check a present header's value and return PASS/WARN.
    _decode_jwt_claims: Decode a JWT without verifying signature; return header+payload.
    _check_cookies: Parse Set-Cookie headers and return session cookie AuthFindings.
    _looks_like_secret: Heuristic test for whether a URL param value is a credential.
    _detect_auth: Run the full authentication detection pass and return AuthFindings.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse

from sentry.config.headers import (
    APIKEY_AMBIGUOUS_URL_PARAMS,
    AUTH_SECURITY_FLAGS,
    AUTH_SIGNATURES,
    HARMFUL_HEADERS,
    HARMFUL_PENALTY,
    RECOMMENDED_HEADERS,
)
from sentry.core.detector import ApiType, DetectionResult, detect_api_type, get_excluded_headers


# ---------------------------------------------------------------------------
# Severity-weighted deduction values for missing recommended headers.
# HIGH missing headers cost more than LOW because their absence has a greater
# real-world impact on endpoint security.
# ---------------------------------------------------------------------------
_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    """
    Analysis result for a single header rule applied to one endpoint response.

    Attributes:
        name (str): HTTP header name evaluated.
        status (str): 'PASS', 'WARN', or 'FAIL'.
        severity (str): Rule severity — 'HIGH', 'MEDIUM', or 'LOW'.
        description (str): Why this status was assigned.
        recommendation (Optional[str]): Suggested header value; None when status is PASS.
        actual_value (Optional[str]): The observed header value, or None if absent.

    Example:
        HeaderFinding(
            name="Strict-Transport-Security",
            status="WARN",
            severity="HIGH",
            description="max-age is 3600 — recommended minimum is 31536000 (1 year)",
            recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
            actual_value="max-age=3600",
        )
    """

    name: str
    status: str
    severity: str
    description: str
    recommendation: Optional[str] = None
    actual_value: Optional[str] = None


@dataclass
class AuthFinding:
    """
    Detection result for one authentication mechanism found on an endpoint.

    Attributes:
        auth_type (str): Mechanism name — 'basic', 'bearer', 'apikey', 'hmac',
                         'mtls', 'session', or 'oauth2'.
        flags (list[str]): Misconfiguration flag IDs from AUTH_SECURITY_FLAGS
                           (e.g. 'basic_over_http'). Empty list means the mechanism
                           was detected but no misconfigurations were found.
        details (str): Human-readable description of the detection evidence.
        token_info (dict): Decoded JWT header/payload claims when auth_type is
                           'bearer'; empty dict for all other types.

    Example:
        AuthFinding(
            auth_type="bearer",
            flags=["jwt_alg_none"],
            details="Authorization: Bearer — JWT alg:none detected",
            token_info={"alg": "none", "typ": "JWT"},
        )
    """

    auth_type: str
    flags: list[str] = field(default_factory=list)
    details: str = ""
    token_info: dict = field(default_factory=dict)


@dataclass
class EndpointResult:
    """
    Aggregated security analysis result for a single scanned URL.

    Populated by analyze_headers() and consumed by the reporter and rendering
    layer. The score and grade summarise the header findings; auth_findings
    carry authentication-specific observations as a parallel list.

    Attributes:
        url (str): The URL that was analysed.
        score (int): Security score 0–100 (100 = perfect).
        grade (str): Letter grade derived from the score (A/B/C/D/F).
        api_type (str): Detected API protocol type string (e.g. 'graphql').
        findings (list[HeaderFinding]): One entry per evaluated header rule.
        auth_findings (list[AuthFinding]): One entry per detected auth mechanism.
        raw_headers (dict[str, str]): Original response headers for reference.

    Example:
        result = analyze_headers("https://api.example.com/graphql",
                                 {"Content-Type": "application/json"})
        print(result.grade)   # "D"
        print(result.score)   # 30
    """

    url: str
    score: int = 100
    grade: str = "A"
    api_type: str = "unknown"
    findings: list[HeaderFinding] = field(default_factory=list)
    auth_findings: list[AuthFinding] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Core public functions
# ---------------------------------------------------------------------------

def score_to_grade(score: int) -> str:
    """
    Convert a numeric security score to a letter grade.

    Thresholds align with SCORE_GOOD (80) and SCORE_MODERATE (50) from
    headers.py and mirror common web-security grading scales so that reports
    are immediately interpretable.

    Args:
        score (int): Score from 0 to 100 as produced by analyze_headers.

    Returns:
        str: One of 'A' (80–100), 'B' (65–79), 'C' (50–64), 'D' (30–49),
             'F' (0–29).
    """
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def analyze_headers(
    url: str,
    response_headers: dict[str, str],
    api_type: Optional[ApiType] = None,
    request_headers: Optional[dict[str, str]] = None,
    body_sample: Optional[str] = None,
    status_code: int = 200,
) -> EndpointResult:
    """
    Run security header analysis and authentication detection on one endpoint.

    Pass 1 evaluates every rule in RECOMMENDED_HEADERS (deducting points for
    absent or weak headers) and every rule in HARMFUL_HEADERS (deducting points
    for exposed technology information). Headers excluded for the detected API
    type are silently skipped.

    Pass 2 runs authentication detection against request headers, URL
    parameters, and response Set-Cookie headers. Detected mechanisms are
    checked against AUTH_SECURITY_FLAGS and any misconfigurations are attached
    as AuthFinding objects.

    Args:
        url (str): Full request URL — used for HTTPS check and URL param scan.
        response_headers (dict[str, str]): Response headers from the endpoint.
        api_type (Optional[ApiType]): Pre-detected API type; if None, detect
                                      automatically from the available signals.
        request_headers (Optional[dict[str, str]]): Request headers captured by
                                                     the interceptor (passive) or
                                                     sent by the scanner (active).
                                                     Pass None in active mode
                                                     when original request headers
                                                     are unavailable.
        body_sample (Optional[str]): First ~2 KB of response body, used by the
                                      API type auto-detector when api_type is None.
        status_code (int): HTTP response status code, passed to the detector.

    Returns:
        EndpointResult: Fully populated result including score, grade, per-header
                        findings, and authentication findings.
    """
    # Normalise to lowercase for all comparisons
    resp_lower: dict[str, str] = {k.lower(): v for k, v in response_headers.items()}
    req_lower: dict[str, str] = {k.lower(): v for k, v in (request_headers or {}).items()}

    # Auto-detect the API type when the caller did not provide one
    if api_type is None:
        detection: DetectionResult = detect_api_type(
            url=url,
            status_code=status_code,
            response_headers=response_headers,
            body_sample=body_sample,
            request_headers=request_headers,
        )
        api_type = detection.api_type

    # Build a lowercase set of excluded header names for O(1) lookup
    excluded_lower: set[str] = {
        h.lower() for h in get_excluded_headers(api_type)
    }

    # --- Pass 1a: recommended headers ------------------------------------
    score: int = 100
    findings: list[HeaderFinding] = []

    for rule in RECOMMENDED_HEADERS:
        if rule.name.lower() in excluded_lower:
            continue

        actual = resp_lower.get(rule.name.lower())
        if actual is None:
            # Header is absent — FAIL and deduct severity-weighted points
            deduction = _SEVERITY_DEDUCTIONS.get(rule.severity, 5)
            score -= deduction
            findings.append(HeaderFinding(
                name=rule.name,
                status="FAIL",
                severity=rule.severity,
                description=rule.description,
                recommendation=rule.recommendation,
                actual_value=None,
            ))
        else:
            # Header is present — check if the value meets quality standards
            warn_reason = _evaluate_header_quality(rule.name, actual)
            if warn_reason:
                # Present but suboptimal: deduct half the severity penalty
                score -= _SEVERITY_DEDUCTIONS.get(rule.severity, 5) // 2
                findings.append(HeaderFinding(
                    name=rule.name,
                    status="WARN",
                    severity=rule.severity,
                    description=warn_reason,
                    recommendation=rule.recommendation,
                    actual_value=actual,
                ))
            else:
                findings.append(HeaderFinding(
                    name=rule.name,
                    status="PASS",
                    severity=rule.severity,
                    description="Header present and value meets security standards.",
                    recommendation=None,
                    actual_value=actual,
                ))

    # --- Pass 1b: harmful headers ----------------------------------------
    for rule in HARMFUL_HEADERS:
        if rule.name.lower() in excluded_lower:
            continue

        actual = resp_lower.get(rule.name.lower())
        if actual is not None:
            score -= HARMFUL_PENALTY
            findings.append(HeaderFinding(
                name=rule.name,
                status="FAIL",
                severity=rule.severity,
                description=f"{rule.description}. Value observed: {actual}",
                recommendation=rule.recommendation,
                actual_value=actual,
            ))
        else:
            findings.append(HeaderFinding(
                name=rule.name,
                status="PASS",
                severity=rule.severity,
                description="Header absent — good.",
                recommendation=None,
                actual_value=None,
            ))

    score = max(0, score)

    # --- Pass 2: authentication detection --------------------------------
    auth_findings = _detect_auth(url, req_lower, resp_lower)

    # --- Pass 3: CORS misconfiguration detection -------------------------
    auth_findings.extend(_analyze_cors(resp_lower, req_lower))

    return EndpointResult(
        url=url,
        score=score,
        grade=score_to_grade(score),
        api_type=api_type.value,
        findings=findings,
        auth_findings=auth_findings,
        raw_headers=dict(response_headers),
    )


# ---------------------------------------------------------------------------
# Header quality evaluation
# ---------------------------------------------------------------------------

def _evaluate_header_quality(name: str, value: str) -> Optional[str]:
    """
    Check a present header's value against quality standards and return a
    WARN reason string, or None if the value is acceptable.

    Called for every header that is present in the response. A non-None return
    value causes a WARN finding with a half-severity score deduction rather than
    a FAIL with full deduction.

    Args:
        name (str): HTTP header name (canonical casing from RECOMMENDED_HEADERS).
        value (str): The raw header value as received from the server.

    Returns:
        Optional[str]: A human-readable explanation of the quality problem, or
                       None if the value is acceptable.
    """
    name_lower = name.lower()
    val_lower = value.lower().strip()

    if name_lower == "strict-transport-security":
        return _check_sts_quality(val_lower)

    if name_lower == "content-security-policy":
        return _check_csp_quality(val_lower)

    if name_lower == "x-content-type-options":
        if val_lower != "nosniff":
            return f"Value must be 'nosniff'; got '{value}'"
        return None

    if name_lower == "x-frame-options":
        if val_lower not in ("deny", "sameorigin"):
            return f"Value should be 'DENY' or 'SAMEORIGIN'; got '{value}'"
        return None

    if name_lower == "cache-control":
        return _check_cache_control_quality(val_lower)

    if name_lower == "referrer-policy":
        # Policies that still leak full URLs are suboptimal for an API context
        unsafe_policies = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
        if val_lower in unsafe_policies:
            return f"Policy '{value}' sends referrer data cross-origin; prefer 'strict-origin-when-cross-origin'"
        return None

    return None


def _check_sts_quality(val_lower: str) -> Optional[str]:
    """
    Evaluate a Strict-Transport-Security header value for common weaknesses.

    Checks max-age is at least one year and that includeSubDomains is present.
    Both are recommended by OWASP for API endpoints.

    Args:
        val_lower (str): Lowercased STS header value.

    Returns:
        Optional[str]: Warning reason, or None if value is acceptable.
    """
    # Extract max-age integer value
    match = re.search(r"max-age\s*=\s*(\d+)", val_lower)
    if not match:
        return "max-age directive is missing from Strict-Transport-Security"

    max_age = int(match.group(1))
    if max_age < 31536000:
        return (
            f"max-age={max_age} is less than 31536000 (1 year); "
            "short max-age allows downgrade windows after expiry"
        )

    if "includesubdomains" not in val_lower:
        return (
            "includeSubDomains is missing; subdomains may be accessible over HTTP "
            "and used as a downgrade vector"
        )

    return None


def _check_csp_quality(val_lower: str) -> Optional[str]:
    """
    Evaluate a Content-Security-Policy value for unsafe directives.

    Flags unsafe-inline and unsafe-eval in any src directive, and wildcard
    default-src which makes the policy effectively permissive.

    Args:
        val_lower (str): Lowercased CSP header value.

    Returns:
        Optional[str]: Warning reason, or None if value is acceptable.
    """
    problems: list[str] = []

    if "'unsafe-inline'" in val_lower:
        problems.append("'unsafe-inline' allows inline script/style execution")
    if "'unsafe-eval'" in val_lower:
        problems.append("'unsafe-eval' permits eval() and similar dangerous functions")
    if "default-src *" in val_lower or "default-src: *" in val_lower:
        problems.append("default-src * is equivalent to no policy")

    return "; ".join(problems) if problems else None


def _check_cache_control_quality(val_lower: str) -> Optional[str]:
    """
    Evaluate a Cache-Control header value for API response caching risks.

    no-cache allows revalidation but still permits cached storage; API
    responses with sensitive data require no-store to prevent any storage.

    Args:
        val_lower (str): Lowercased Cache-Control header value.

    Returns:
        Optional[str]: Warning reason, or None if value is acceptable.
    """
    if "no-store" not in val_lower:
        if "no-cache" in val_lower:
            return (
                "no-cache permits cached storage with revalidation; "
                "API responses should use no-store to prevent sensitive data being cached"
            )
        return (
            f"Value '{val_lower}' does not include no-store; "
            "cached API responses may expose sensitive data"
        )
    return None


# ---------------------------------------------------------------------------
# JWT decoding
# ---------------------------------------------------------------------------

def _decode_jwt_claims(token: str) -> tuple[dict, dict]:
    """
    Decode a JWT token's header and payload without verifying the signature.

    Uses only stdlib base64 and json. The signature is not checked — we only
    need the claims to detect misconfigurations (alg:none, missing exp).

    Args:
        token (str): Raw JWT string in the form header.payload.signature.

    Returns:
        tuple[dict, dict]: (header_claims, payload_claims). Both dicts are empty
                           if decoding fails (malformed token, not a JWT, etc.).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}

    def _decode_segment(segment: str) -> dict:
        # base64url padding is omitted in JWTs; add it back before decoding
        padded = segment + "=" * (4 - len(segment) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return {}

    return _decode_segment(parts[0]), _decode_segment(parts[1])


# ---------------------------------------------------------------------------
# Cookie analysis
# ---------------------------------------------------------------------------

def _check_cookies(resp_lower: dict[str, str]) -> list[AuthFinding]:
    """
    Parse Set-Cookie response headers and return AuthFindings for session cookies.

    Checks each detected session/auth cookie name against the patterns in
    AUTH_SIGNATURES['session'].cookie_name_patterns and flags missing Secure,
    HttpOnly, and SameSite attributes.

    Args:
        resp_lower (dict[str, str]): Lowercased response headers.

    Returns:
        list[AuthFinding]: One AuthFinding per detected session cookie,
                           with flags for each missing security attribute.
    """
    # mitmproxy and requests fold multiple Set-Cookie headers into a single
    # comma-separated value; we process each segment independently
    raw = resp_lower.get("set-cookie", "")
    if not raw:
        return []

    findings: list[AuthFinding] = []
    session_patterns = AUTH_SIGNATURES["session"].cookie_name_patterns

    # Multiple Set-Cookie headers are commonly folded into a single
    # comma-joined value (the requests library does this). A naive split on
    # "," would also break inside the Expires=<HTTP-date> attribute, whose
    # value contains a comma ("Expires=Wed, 21 Oct 2025 07:28:00 GMT") — that
    # fragmentation previously produced phantom missing-flag findings on
    # perfectly secure cookies. Split only on commas that introduce a new
    # "cookie-name=" pair; commas inside an attribute value are left intact.
    for cookie_str in re.split(r",\s*(?=[^=;,]+=)", raw):
        cookie_str = cookie_str.strip()
        if not cookie_str:
            continue

        # Cookie name is everything before the first '='
        name_part = cookie_str.split(";")[0].split("=")[0].strip().lower()
        cookie_lower = cookie_str.lower()

        # Only analyse cookies that match known session/auth name patterns
        is_session_cookie = any(pattern in name_part for pattern in session_patterns)
        if not is_session_cookie:
            continue

        flags: list[str] = []
        # Check for each required security attribute (case-insensitive within value)
        if "secure" not in cookie_lower:
            flags.append("cookie_missing_secure")
        if "httponly" not in cookie_lower:
            flags.append("cookie_missing_httponly")
        if "samesite" not in cookie_lower:
            flags.append("cookie_missing_samesite")

        findings.append(AuthFinding(
            auth_type="session",
            flags=flags,
            details=f"Session cookie '{name_part}' detected in Set-Cookie response header.",
            token_info={},
        ))

    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration detection
# ---------------------------------------------------------------------------

def _analyze_cors(
    resp_lower: dict[str, str],
    req_lower: dict[str, str],
) -> list[AuthFinding]:
    """
    Detect CORS misconfiguration in response headers and return AuthFindings.

    Checks Access-Control-Allow-Origin for wildcard and reflected-origin
    patterns, flags dangerous combinations with Access-Control-Allow-Credentials,
    and warns when Vary: Origin is absent from CORS responses.

    In active mode, req_lower contains the probe Origin header sent by the
    OPTIONS preflight. In passive mode, req_lower contains the real browser
    request headers captured by mitmproxy.

    Args:
        resp_lower (dict[str, str]): Lowercased response headers.
        req_lower (dict[str, str]): Lowercased request headers (may be empty).

    Returns:
        list[AuthFinding]: One entry per detected CORS issue. Empty list when
                           no CORS headers are present or no issues are found.
    """
    acao = resp_lower.get("access-control-allow-origin", "").strip()
    if not acao:
        return []

    findings: list[AuthFinding] = []
    acac = resp_lower.get("access-control-allow-credentials", "").strip().lower()
    vary = resp_lower.get("vary", "").lower()
    credentials_true = acac == "true"

    if acao == "*":
        if credentials_true:
            findings.append(AuthFinding(
                auth_type="cors",
                flags=["cors_wildcard_with_credentials"],
                details=(
                    "Access-Control-Allow-Origin: * with Allow-Credentials: true. "
                    "Browsers reject this per spec, but the server config is broken."
                ),
                token_info={},
            ))
        else:
            findings.append(AuthFinding(
                auth_type="cors",
                flags=["cors_wildcard_origin"],
                details="Access-Control-Allow-Origin: * allows any origin to read this response.",
                token_info={},
            ))
    else:
        # Check for origin reflection: server echoes back whatever Origin was sent
        sent_origin = req_lower.get("origin", "").strip()
        if sent_origin and acao == sent_origin:
            if credentials_true:
                findings.append(AuthFinding(
                    auth_type="cors",
                    flags=["cors_reflected_origin_with_credentials"],
                    details=(
                        f"Server reflects Origin '{sent_origin}' with Allow-Credentials: true. "
                        "Any website can make authenticated cross-origin requests to this endpoint."
                    ),
                    token_info={},
                ))
            else:
                findings.append(AuthFinding(
                    auth_type="cors",
                    flags=["cors_reflected_origin"],
                    details=(
                        f"Server reflects the request Origin '{sent_origin}' verbatim. "
                        "Verify this origin is validated against a whitelist, not echoed blindly."
                    ),
                    token_info={},
                ))

    # Vary: Origin must be present whenever the allowed origin is dynamic
    # (a specific or reflected origin), otherwise a cache may serve that
    # origin-specific response to a request from a different origin. It is
    # irrelevant for a static "Access-Control-Allow-Origin: *", which is
    # identical for every origin — flagging it there is a false positive.
    if acao != "*" and "origin" not in vary:
        findings.append(AuthFinding(
            auth_type="cors",
            flags=["cors_missing_vary_origin"],
            details=(
                "Access-Control-Allow-Origin is set but Vary: Origin is absent. "
                "CDN or reverse-proxy caches may serve this response to other origins."
            ),
            token_info={},
        ))

    return findings


# ---------------------------------------------------------------------------
# URL parameter secret heuristic
# ---------------------------------------------------------------------------

def _looks_like_secret(value: str) -> bool:
    """
    Heuristically decide whether a URL parameter value looks like a credential.

    Used to gate the generic query-parameter names in APIKEY_AMBIGUOUS_URL_PARAMS
    (key / token / auth) so that obviously non-secret values such as ?key=name,
    ?token=1, or ?auth=true do not raise a false apikey_in_url finding. A value is
    treated as a secret when it is at least eight characters of token-charset text
    and either mixes letters and digits (the classic API-key shape) or is a long
    opaque string (e.g. a hex digest or base64 token).

    Args:
        value (str): Raw query-parameter value as it appeared in the URL.

    Returns:
        bool: True if the value resembles a credential, False otherwise.
    """
    v = value.strip()
    if len(v) < 8:
        return False
    if v.lower() in {"true", "false", "null", "none", "undefined"}:
        return False
    # Reject anything containing characters a token would not use (spaces, etc.)
    if not re.fullmatch(r"[A-Za-z0-9._\-+/=]+", v):
        return False
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    # Classic API-key / token shape mixes letter and digit classes; failing that,
    # a long opaque string is still credential-like (hex digest, base64 blob).
    if has_digit and has_alpha:
        return True
    return len(v) >= 24


# ---------------------------------------------------------------------------
# Authentication detection
# ---------------------------------------------------------------------------

def _detect_auth(
    url: str,
    req_lower: dict[str, str],
    resp_lower: dict[str, str],
) -> list[AuthFinding]:
    """
    Detect authentication mechanisms in request and response headers and flag
    any misconfigurations found.

    Checks are performed in this order: Authorization header, API key headers,
    HMAC signature headers, mTLS forwarded certificate headers, API key URL
    parameters, session cookies, and OAuth 2.0 response headers.

    Args:
        url (str): Full request URL — used for the HTTPS check and URL param scan.
        req_lower (dict[str, str]): Lowercased request headers.
        resp_lower (dict[str, str]): Lowercased response headers.

    Returns:
        list[AuthFinding]: One entry per detected auth mechanism. An entry with
                           an empty flags list means the mechanism was detected
                           but no misconfigurations were found.
    """
    findings: list[AuthFinding] = []
    is_http = url.startswith("http://")

    parsed = urlparse(url)
    # Map lowercase query-parameter name -> list of values. Values are needed for
    # the secret heuristic applied to generic parameter names.
    url_params: dict[str, list[str]] = {
        k.lower(): v for k, v in parse_qs(parsed.query).items()
    }

    auth_header = req_lower.get("authorization", "")

    # --- Basic Auth -------------------------------------------------------
    if auth_header.lower().startswith("basic "):
        flags: list[str] = []
        if is_http:
            flags.append("basic_over_http")
        # Credentials embedded in URL: http://user:pass@host/path
        if parsed.username or parsed.password:
            flags.append("basic_in_url")
        findings.append(AuthFinding(
            auth_type="basic",
            flags=flags,
            details="Basic Auth credentials detected in Authorization header.",
            token_info={},
        ))

    # --- Bearer / JWT (and OAuth 2.0) ------------------------------------
    elif auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        header_claims, payload_claims = _decode_jwt_claims(token)

        flags = []
        token_info: dict = {}

        if header_claims:
            # Token decoded successfully — it is a JWT
            token_info = {**header_claims, **{f"payload.{k}": v for k, v in payload_claims.items()}}
            alg = header_claims.get("alg", "")
            if alg.lower() == "none":
                flags.append("jwt_alg_none")
            if "exp" not in payload_claims:
                flags.append("jwt_no_expiry")

        if is_http:
            flags.append("bearer_over_http")

        # Distinguish OAuth 2.0 from plain Bearer by checking OAuth response headers
        oauth_resp_headers = AUTH_SIGNATURES["oauth2"].response_header_names
        is_oauth = any(h in resp_lower for h in oauth_resp_headers)
        auth_type = "oauth2" if is_oauth else "bearer"

        findings.append(AuthFinding(
            auth_type=auth_type,
            flags=flags,
            details=(
                f"{'OAuth 2.0 Bearer' if is_oauth else 'Bearer'} token detected in "
                f"Authorization header. {'JWT decoded.' if header_claims else 'Not a JWT or decode failed.'}"
            ),
            token_info=token_info,
        ))

    # --- HMAC Authorization prefix ----------------------------------------
    elif auth_header.lower().startswith("hmac "):
        findings.append(AuthFinding(
            auth_type="hmac",
            flags=[],
            details="HMAC Authorization header detected.",
            token_info={},
        ))

    # --- Named API key request headers ------------------------------------
    api_key_sig = AUTH_SIGNATURES["apikey"]
    matched_key_header: Optional[str] = None
    for header_name in api_key_sig.request_header_names:
        if header_name in req_lower:
            matched_key_header = header_name
            break

    if matched_key_header:
        flags = []
        if is_http:
            flags.append("apikey_over_http")
        findings.append(AuthFinding(
            auth_type="apikey",
            flags=flags,
            details=f"API key detected in request header '{matched_key_header}'.",
            token_info={},
        ))

    # --- HMAC signature headers (webhook style) ---------------------------
    hmac_sig = AUTH_SIGNATURES["hmac"]
    for header_name in hmac_sig.request_header_names:
        if header_name in req_lower:
            flags = []
            # x-hub-signature uses SHA1 (legacy); flag it if no SHA256 counterpart
            if header_name == "x-hub-signature" and "x-hub-signature-256" not in req_lower:
                flags.append("hmac_sha1")
            findings.append(AuthFinding(
                auth_type="hmac",
                flags=flags,
                details=f"HMAC signature detected in request header '{header_name}'.",
                token_info={},
            ))
            break  # one HMAC finding per endpoint is sufficient

    # --- mTLS forwarded certificate headers -------------------------------
    mtls_sig = AUTH_SIGNATURES["mtls"]
    for header_name in mtls_sig.request_header_names + mtls_sig.response_header_names:
        if header_name in req_lower or header_name in resp_lower:
            findings.append(AuthFinding(
                auth_type="mtls",
                flags=[],
                details=f"mTLS client certificate forwarded via '{header_name}'.",
                token_info={},
            ))
            break

    # --- API key in URL parameters ----------------------------------------
    # Unambiguous credential parameter names always flag. Generic names
    # (key/token/auth) flag only when the value looks like a real secret, so
    # ?key=name, ?token=1, and ?auth=true are not reported as leaked keys.
    matched_param: Optional[str] = None
    for param_name in api_key_sig.url_param_names:
        if param_name in url_params:
            matched_param = param_name
            break
    if matched_param is None:
        for param_name in APIKEY_AMBIGUOUS_URL_PARAMS:
            values = url_params.get(param_name)
            if values and any(_looks_like_secret(v) for v in values):
                matched_param = param_name
                break
    if matched_param:
        flags = ["apikey_in_url"]
        if is_http:
            flags.append("apikey_over_http")
        findings.append(AuthFinding(
            auth_type="apikey",
            flags=flags,
            details=f"API key transmitted as URL query parameter '{matched_param}'.",
            token_info={},
        ))

    # --- Session cookies from Set-Cookie response headers -----------------
    findings.extend(_check_cookies(resp_lower))

    # --- WWW-Authenticate challenge (active mode — no request headers) ----
    # When Sentry probes without credentials, a 401 with WWW-Authenticate
    # reveals what auth types the API supports. Report the type without flags
    # since we cannot assess transport security from the challenge alone.
    www_auth = resp_lower.get("www-authenticate", "")
    if www_auth and not auth_header:
        # Only report if we didn't already detect auth from request headers
        if "basic" in www_auth.lower():
            findings.append(AuthFinding(
                auth_type="basic",
                flags=[],
                details="WWW-Authenticate response header indicates Basic Auth is supported.",
                token_info={},
            ))
        elif "bearer" in www_auth.lower():
            auth_type = "oauth2" if "scope" in www_auth.lower() else "bearer"
            findings.append(AuthFinding(
                auth_type=auth_type,
                flags=[],
                details="WWW-Authenticate response header indicates Bearer token auth is supported.",
                token_info={},
            ))

    return findings
