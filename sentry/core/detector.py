"""
detector.py

Identifies the API protocol type of a target endpoint so that core.analyzer
can apply the correct header rule set and exclude inapplicable rules. Detection
is heuristic: it scores each known type against observed signals (Content-Type,
response headers, URL path, URL query parameters, optional request headers, and
an optional body sample), then returns the type with the highest confidence score.

Scoring uses weighted signal categories. Specific signals — e.g. a grpc-status
response trailer or a <soap:Envelope body fragment — carry high weight and are
unambiguous. Generic signals — e.g. application/json content type — carry low
weight and only influence the result when no stronger signal is present.

REST is the fallback: if no type exceeds the minimum specificity threshold but
the response looks like plain HTTP/JSON, the function returns REST rather than
UNKNOWN. UNKNOWN is reserved for responses with no recognisable signals at all.

Classes:
    ApiType: Enumeration of all recognised API protocol types.
    DetectionResult: Dataclass carrying the final type, confidence score, and
                     the matched signals that contributed to the decision.

Functions:
    detect_api_type: Score all known types and return the best match.
    get_excluded_headers: Return header names to skip for a given ApiType.
    _normalise_headers: Lowercase all keys and values in a header dict.
    _extract_content_type: Strip charset/boundary from a Content-Type string.
    _score_type: Compute the confidence score for one API type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import parse_qs, urlparse

from sentry.config.headers import API_SIGNATURES, EXCLUDED_HEADERS


class ApiType(str, Enum):
    """
    Recognised API protocol types that influence which header rules apply.

    Inherits from str so instances serialise cleanly to JSON without a custom
    encoder (e.g. json.dumps({"type": ApiType.GRPC}) produces "grpc").

    Attributes:
        REST: Standard HTTP REST API returning JSON or similar structured data.
        GRPC: gRPC service using HTTP/2 with protobuf or JSON transcoding.
        GRAPHQL: GraphQL endpoint, typically served at a single /graphql path.
        SOAP: SOAP/XML web service.
        WEBHOOK: Inbound webhook endpoint identified by vendor signature headers.
        JSONRPC: JSON-RPC 2.0 service.
        ODATA: OData v3/v4 REST service with system query options.
        UNKNOWN: No recognisable signals; analysis uses the full rule set.
    """

    REST = "rest"
    GRPC = "grpc"
    GRAPHQL = "graphql"
    SOAP = "soap"
    WEBHOOK = "webhook"
    JSONRPC = "jsonrpc"
    ODATA = "odata"
    UNKNOWN = "unknown"


# Map from ApiSignature key strings to ApiType members.
# Used to convert the winner of the scoring round to an enum value.
_KEY_TO_APITYPE: dict[str, ApiType] = {
    "rest": ApiType.REST,
    "grpc": ApiType.GRPC,
    "graphql": ApiType.GRAPHQL,
    "soap": ApiType.SOAP,
    "webhook": ApiType.WEBHOOK,
    "jsonrpc": ApiType.JSONRPC,
    "odata": ApiType.ODATA,
}

# Tie-breaking order when two types share the same score.
# More specific / rarer types are preferred over general ones so that, e.g.,
# an endpoint at /api/v1/graphql is identified as GraphQL not REST.
_TIEBREAK_PRIORITY: dict[ApiType, int] = {
    ApiType.GRPC: 0,
    ApiType.SOAP: 1,
    ApiType.GRAPHQL: 2,
    ApiType.ODATA: 3,
    ApiType.JSONRPC: 4,
    ApiType.WEBHOOK: 5,
    ApiType.REST: 6,
    ApiType.UNKNOWN: 7,
}

# Point values for each signal category.
# Higher weight = stronger discriminating power for this type of signal.
_W_BODY = 40         # Body fragment match — highly specific (e.g. <soap:Envelope)
_W_RESP_HEADER = 35  # Type-specific response header (e.g. grpc-status)
_W_CONTENT_TYPE = 30 # Unique Content-Type (e.g. application/grpc)
_W_REQ_HEADER = 20   # Type-specific request header (e.g. X-Apollo-Operation-Name)
_W_PATH = 20         # URL path substring (e.g. /graphql)
_W_URL_PARAM = 10    # URL query parameter name (e.g. $filter)
_W_GENERIC_CT = 5    # Generic Content-Type shared by many types (e.g. application/json)

# These content types appear across many API types; weigh them lightly so they
# act as a weak REST signal rather than dominating the result.
_GENERIC_CONTENT_TYPES = frozenset({
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
})

# Minimum total score needed to claim any *specific* type (i.e. not REST/UNKNOWN).
# 25 means a path match alone (20 pts) is NOT enough — at least two weak signals
# or one strong signal is required. This prevents /graphql from winning when the
# response gives no other corroboration.
_MIN_SCORE_SPECIFIC = 25

# Minimum score for REST — lower because REST is the most common default and
# a single version-path or JSON content type is a reasonable indicator.
_MIN_SCORE_REST = 5


@dataclass
class DetectionResult:
    """
    Output of detect_api_type carrying the decision and supporting evidence.

    Attributes:
        api_type (ApiType): The detected protocol type.
        score (int): Confidence score that determined this type.
        matched_signals (list[str]): Human-readable descriptions of each
            signal that contributed to the score, for debug output and
            verbose logging.

    Example:
        DetectionResult(
            api_type=ApiType.GRAPHQL,
            score=60,
            matched_signals=["path:/graphql (20)", "body:__schema (40)"],
        )
    """

    api_type: ApiType
    score: int
    matched_signals: list[str] = field(default_factory=list)


def _normalise_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Return a copy of the header dict with all keys and values lowercased.

    HTTP header names are case-insensitive per RFC 7230. Normalising to
    lowercase lets all comparisons use simple string equality.

    Args:
        headers (dict[str, str]): Raw header dict from requests or mitmproxy.

    Returns:
        dict[str, str]: New dict with lowercase keys and values.
    """
    return {k.lower(): v.lower() for k, v in headers.items()}


def _extract_content_type(headers_lower: dict[str, str]) -> str:
    """
    Extract the bare media type from the Content-Type header value.

    Strips parameters such as charset, boundary, and version qualifiers so
    that 'application/json; charset=utf-8' matches the pattern 'application/json'.

    Args:
        headers_lower (dict[str, str]): Header dict with lowercase keys.

    Returns:
        str: Bare media type in lowercase (e.g. 'application/grpc'), or an
             empty string if Content-Type is absent.
    """
    raw = headers_lower.get("content-type", "")
    # Everything before the first semicolon is the media type
    return raw.split(";")[0].strip()


def _score_type(
    type_key: str,
    content_type: str,
    resp_headers: dict[str, str],
    req_headers: dict[str, str],
    url_path_lower: str,
    url_param_names: set[str],
    body: str,
) -> tuple[int, list[str]]:
    """
    Compute the confidence score for one API type key against all available signals.

    Each matched signal adds points to the total. The matched_signals list
    records a short description of each hit for debug output.

    Args:
        type_key (str): Key into API_SIGNATURES (e.g. 'graphql').
        content_type (str): Bare Content-Type value (lowercase, no params).
        resp_headers (dict[str, str]): Lowercased response headers.
        req_headers (dict[str, str]): Lowercased request headers (may be empty).
        url_path_lower (str): Lowercase URL path component.
        url_param_names (set[str]): Lowercase URL query parameter names.
        body (str): Response body sample (may be empty string).

    Returns:
        tuple[int, list[str]]: (total_score, list_of_matched_signal_descriptions)
    """
    sig = API_SIGNATURES[type_key]
    score = 0
    signals: list[str] = []

    # --- Content-Type matching --------------------------------------------
    for ct_pattern in sig.content_types:
        # Use exact equality OR a structured-subtype suffix match so that
        # 'application/grpc' matches 'application/grpc+proto', but
        # 'application/json' does NOT match 'application/json-rpc'.
        # The '+' check handles RFC 6839 structured syntax subtypes only.
        ct_match = (
            content_type == ct_pattern
            or content_type.startswith(ct_pattern + "+")
        )
        if ct_match:
            if ct_pattern in _GENERIC_CONTENT_TYPES:
                score += _W_GENERIC_CT
                signals.append(f"content-type:{ct_pattern} (generic, +{_W_GENERIC_CT})")
            else:
                score += _W_CONTENT_TYPE
                signals.append(f"content-type:{ct_pattern} (+{_W_CONTENT_TYPE})")
            # Count the content-type once even if multiple patterns could match
            break

    # --- Response header matching -----------------------------------------
    for header in sig.response_headers:
        if header in resp_headers:
            score += _W_RESP_HEADER
            signals.append(f"resp-header:{header} (+{_W_RESP_HEADER})")

    # --- Request header matching ------------------------------------------
    for header in sig.request_headers:
        if header in req_headers:
            score += _W_REQ_HEADER
            signals.append(f"req-header:{header} (+{_W_REQ_HEADER})")

    # --- URL path pattern matching ----------------------------------------
    for pattern in sig.path_patterns:
        if pattern in url_path_lower:
            score += _W_PATH
            signals.append(f"path:{pattern} (+{_W_PATH})")
            # Count the first matching path pattern only to avoid inflating
            # the score for overlapping patterns on the same URL
            break

    # --- URL query parameter matching -------------------------------------
    for param in sig.url_param_names:
        if param in url_param_names:
            score += _W_URL_PARAM
            signals.append(f"url-param:{param} (+{_W_URL_PARAM})")

    # --- Body pattern matching --------------------------------------------
    if body:
        for pattern in sig.body_patterns:
            if pattern in body:
                score += _W_BODY
                signals.append(f"body:{pattern!r} (+{_W_BODY})")

    return score, signals


def detect_api_type(
    url: str,
    status_code: int,
    response_headers: dict[str, str],
    body_sample: Optional[str] = None,
    request_headers: Optional[dict[str, str]] = None,
) -> DetectionResult:
    """
    Score all known API types against available signals and return the best match.

    The detection algorithm:
      1. Normalise all inputs (lowercase headers, parse URL components).
      2. Score each type in API_SIGNATURES using _score_type().
      3. Find the highest-scoring non-REST type above _MIN_SCORE_SPECIFIC.
      4. If found, return it. If tied, prefer higher-priority types from
         _TIEBREAK_PRIORITY (more specific types beat more general ones).
      5. If no specific type wins, check if REST exceeds _MIN_SCORE_REST.
      6. If REST wins, return REST. Otherwise return UNKNOWN.

    Args:
        url (str): Full request URL — path and query params are examined.
        status_code (int): HTTP response status code (reserved for future
                           protocol-level heuristics).
        response_headers (dict[str, str]): Response headers from the endpoint.
        body_sample (Optional[str]): First ~2 KB of response body. Pass None
                                      or an empty string if unavailable.
        request_headers (Optional[dict[str, str]]): Request headers observed
                                                     by the interceptor (passive
                                                     mode only). Pass None in
                                                     active mode.

    Returns:
        DetectionResult: The detected type, confidence score, and matched signals.
    """
    # Normalise inputs so all comparisons are case-insensitive
    resp_lower = _normalise_headers(response_headers)
    req_lower = _normalise_headers(request_headers or {})
    body = body_sample or ""

    # Parse URL into path and query parameter name set
    parsed = urlparse(url)
    url_path_lower = parsed.path.lower()
    url_param_names = {k.lower() for k in parse_qs(parsed.query)}

    content_type = _extract_content_type(resp_lower)

    # Score every type defined in headers.py
    all_scores: dict[str, tuple[int, list[str]]] = {}
    for type_key in API_SIGNATURES:
        all_scores[type_key] = _score_type(
            type_key,
            content_type,
            resp_lower,
            req_lower,
            url_path_lower,
            url_param_names,
            body,
        )

    # Find the highest-scoring specific (non-REST) type above threshold
    best_specific_key: Optional[str] = None
    best_specific_score = 0

    for type_key, (score, _) in all_scores.items():
        if type_key == "rest":
            continue
        if score < _MIN_SCORE_SPECIFIC:
            continue
        # Prefer higher score; break ties by type priority
        if score > best_specific_score:
            best_specific_key = type_key
            best_specific_score = score
        elif score == best_specific_score and best_specific_key is not None:
            # Tiebreak: lower priority index = more specific = wins
            current_priority = _TIEBREAK_PRIORITY.get(
                _KEY_TO_APITYPE[best_specific_key], 99
            )
            challenger_priority = _TIEBREAK_PRIORITY.get(
                _KEY_TO_APITYPE[type_key], 99
            )
            if challenger_priority < current_priority:
                best_specific_key = type_key

    if best_specific_key is not None:
        score, signals = all_scores[best_specific_key]
        return DetectionResult(
            api_type=_KEY_TO_APITYPE[best_specific_key],
            score=score,
            matched_signals=signals,
        )

    # No specific type won — check REST
    rest_score, rest_signals = all_scores.get("rest", (0, []))
    if rest_score >= _MIN_SCORE_REST:
        return DetectionResult(
            api_type=ApiType.REST,
            score=rest_score,
            matched_signals=rest_signals,
        )

    # No recognisable signals at all
    return DetectionResult(
        api_type=ApiType.UNKNOWN,
        score=0,
        matched_signals=[],
    )


def get_excluded_headers(api_type: ApiType) -> list[str]:
    """
    Return the list of header names to skip during analysis for this API type.

    Looks up EXCLUDED_HEADERS from sentry/config/headers.py using the ApiType
    value string as the key. Returns an empty list when no exclusions are
    defined for this type.

    Args:
        api_type (ApiType): The detected API type for the target endpoint.

    Returns:
        list[str]: Header names to omit from analysis. May be empty.

    Example:
        get_excluded_headers(ApiType.GRPC)
        # -> ["Content-Security-Policy", "X-Frame-Options"]

        get_excluded_headers(ApiType.REST)
        # -> []
    """
    return EXCLUDED_HEADERS.get(api_type.value, [])
