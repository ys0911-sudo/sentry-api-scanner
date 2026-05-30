"""
headers.py

Central configuration store for all header rules, API type detection
signatures, and authentication detection constants used throughout Sentry.
No logic lives here — this file is pure data that other modules import.

Three categories of data are exported:

  1. Header rules — RECOMMENDED_HEADERS and HARMFUL_HEADERS consumed by
     core.analyzer to evaluate HTTP responses and calculate security scores.

  2. API type signatures — API_SIGNATURES consumed by core.detector to
     identify the protocol type (REST, GraphQL, SOAP, gRPC, Webhook,
     JSON-RPC, OData) from content types, headers, path patterns, URL
     parameters, and body fragments.

  3. Authentication signatures and security flags — AUTH_SIGNATURES and
     AUTH_SECURITY_FLAGS consumed by core.analyzer to detect authentication
     mechanisms in all scan modes and flag misconfigurations.

Classes:
    HeaderRule: Named tuple describing one header security rule.
    ApiSignature: Frozen dataclass holding detection signals for one API type.
    AuthSignature: Frozen dataclass holding detection signals for one auth type.
    AuthSecurityFlag: Named tuple describing one authentication misconfiguration flag.

Constants:
    RECOMMENDED_HEADERS: Rules for security headers that should be present.
    HARMFUL_HEADERS: Rules for headers that should be absent.
    EXCLUDED_HEADERS: Per-API-type header names to skip during analysis.
    SCORE_GOOD, SCORE_MODERATE, HARMFUL_PENALTY: Scoring thresholds.
    SEVERITY_COLORS: Rich colour names per severity level.
    API_SIGNATURES: Detection signal sets keyed by API type name string.
    AUTH_SIGNATURES: Detection signal sets keyed by auth type name string.
    AUTH_SECURITY_FLAGS: Misconfiguration flag definitions keyed by flag id string.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Section 1 — Header security rules
# ---------------------------------------------------------------------------

class HeaderRule(NamedTuple):
    """
    Definition of a single header security rule evaluated by core.analyzer.

    Attributes:
        name (str): Canonical HTTP header name.
        severity (str): Impact level — 'HIGH', 'MEDIUM', or 'LOW'.
        description (str): Why this header matters for security.
        recommendation (str): Exact recommended header value to use.
    """

    name: str
    severity: str
    description: str
    recommendation: str


RECOMMENDED_HEADERS: list[HeaderRule] = [
    HeaderRule(
        name="Strict-Transport-Security",
        severity="HIGH",
        description="Forces HTTPS; missing allows downgrade attacks",
        recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    HeaderRule(
        name="Content-Security-Policy",
        severity="HIGH",
        description="Prevents XSS and data-injection attacks",
        recommendation="Content-Security-Policy: default-src 'self'",
    ),
    HeaderRule(
        name="X-Frame-Options",
        severity="MEDIUM",
        description="Prevents clickjacking via iframes",
        recommendation="X-Frame-Options: DENY",
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        severity="MEDIUM",
        description="Prevents MIME-type sniffing",
        recommendation="X-Content-Type-Options: nosniff",
    ),
    HeaderRule(
        name="Referrer-Policy",
        severity="LOW",
        description="Controls how much referrer info is sent",
        recommendation="Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        name="Permissions-Policy",
        severity="LOW",
        description="Restricts browser feature access",
        recommendation="Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
    HeaderRule(
        name="Cache-Control",
        severity="MEDIUM",
        description="Prevents sensitive API responses from being cached",
        recommendation="Cache-Control: no-store, max-age=0",
    ),
]

HARMFUL_HEADERS: list[HeaderRule] = [
    HeaderRule(
        name="Server",
        severity="LOW",
        description="Exposes server software and version",
        recommendation="Remove or replace with a generic value",
    ),
    HeaderRule(
        name="X-Powered-By",
        severity="LOW",
        description="Exposes backend technology stack",
        recommendation="Remove X-Powered-By from all responses",
    ),
    HeaderRule(
        name="X-AspNet-Version",
        severity="HIGH",
        description="Exposes exact ASP.NET version — enables targeted exploits",
        recommendation="Remove: add <httpRuntime enableVersionHeader='false' /> to Web.config",
    ),
]

# Headers that do not apply to specific API types and should be skipped
# during analysis to avoid false positives in the report.
EXCLUDED_HEADERS: dict[str, list[str]] = {
    "grpc": ["Content-Security-Policy", "X-Frame-Options"],
}

SCORE_GOOD = 80
SCORE_MODERATE = 50
HARMFUL_PENALTY = 5     # points deducted per harmful header present

SEVERITY_COLORS: dict[str, str] = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "CRITICAL": "bold red",
}


# ---------------------------------------------------------------------------
# Section 2 — API type detection signatures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ApiSignature:
    """
    Collection of detection signals for a single API protocol type.

    All fields are tuples of lowercase strings. core.detector compares
    observed request/response attributes against these tuples to identify
    the protocol type. Matching is substring or exact depending on the field.

    Attributes:
        content_types (tuple[str, ...]): Content-Type values that indicate
            this type (lowercase, may be partial for prefix matching).
        request_headers (tuple[str, ...]): Request header names whose
            presence indicates this type (lowercase).
        response_headers (tuple[str, ...]): Response header names whose
            presence indicates this type (lowercase).
        path_patterns (tuple[str, ...]): URL path substrings that suggest
            this type (lowercase).
        url_param_names (tuple[str, ...]): URL query parameter names that
            suggest this type (lowercase).
        body_patterns (tuple[str, ...]): Substrings to look for in the
            request or response body sample (case-sensitive as supplied).
    """

    content_types: tuple[str, ...]
    request_headers: tuple[str, ...]
    response_headers: tuple[str, ...]
    path_patterns: tuple[str, ...]
    url_param_names: tuple[str, ...]
    body_patterns: tuple[str, ...]


API_SIGNATURES: dict[str, ApiSignature] = {

    "rest": ApiSignature(
        content_types=(
            "application/json",
            "application/vnd.api+json",     # JSON:API spec
            "application/hal+json",          # HAL (Hypertext Application Language)
        ),
        request_headers=(
            "x-rapidapi-host",               # RapidAPI marketplace
        ),
        response_headers=(),
        path_patterns=(
            "/api/v1/",
            "/api/v2/",
            "/api/v3/",
            "/api/v4/",
            "/api/v5/",
            "/rest/",
        ),
        url_param_names=(),
        body_patterns=(),
    ),

    "graphql": ApiSignature(
        content_types=(
            "application/graphql",           # raw GraphQL query body
            "application/json",              # most GraphQL over HTTP uses JSON
        ),
        request_headers=(
            "x-apollo-operation-name",       # Apollo client operation name
            "x-apollo-operation-type",       # query | mutation | subscription
        ),
        response_headers=(),
        path_patterns=(
            "/graphql",
            "/graphql/v1",
            "/gql",
        ),
        url_param_names=(),
        body_patterns=(
            "__schema",                      # introspection query — high-confidence signal
            "__typename",                    # field present in most GraphQL queries
            '"query"',                       # JSON body key for GraphQL requests
            '"mutation"',
            '"variables"',
        ),
    ),

    "soap": ApiSignature(
        content_types=(
            "text/xml",
            "application/soap+xml",          # SOAP 1.2 content type
            "application/xml",
        ),
        request_headers=(
            "soapaction",                    # SOAP 1.1 action header (lowercase after normalisation)
        ),
        response_headers=(),
        path_patterns=(
            "/ws/",
            "/wsdl",
            "/service.asmx",
            "/soap/",
        ),
        url_param_names=(
            "wsdl",                          # ?wsdl query param returns the service description
        ),
        body_patterns=(
            "<soap:Envelope",                # SOAP 1.1 namespace prefix
            "<s:Envelope",                   # WCF / .NET SOAP common prefix
            "<SOAP-ENV:Envelope",            # SOAP 1.2 namespace prefix
        ),
    ),

    "grpc": ApiSignature(
        content_types=(
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",         # gRPC-JSON transcoding
            "application/grpc-web",          # gRPC-Web (browser proxy)
            "application/grpc-web+proto",
        ),
        request_headers=(),
        response_headers=(
            "grpc-status",                   # always present in gRPC trailers
            "grpc-message",                  # error detail when status != 0
            "grpc-encoding",                 # compression algorithm in use
        ),
        path_patterns=(
            "/grpc.",                        # protobuf package.ServiceName convention
        ),
        url_param_names=(),
        body_patterns=(),
    ),

    "webhook": ApiSignature(
        content_types=(
            "application/json",
            "application/x-www-form-urlencoded",
        ),
        request_headers=(
            # GitHub — most common webhook provider; omitted from original spec
            "x-github-event",               # event type (push, pull_request, etc.)
            "x-github-delivery",            # unique delivery UUID per webhook call
            "x-hub-signature",              # HMAC-SHA1 of payload (legacy)
            "x-hub-signature-256",          # HMAC-SHA256 of payload (current)
            # Shopify
            "x-shopify-hmac-sha256",
            "x-shopify-topic",
            # GitLab
            "x-gitlab-event",
            "x-gitlab-token",
            # Bitbucket
            "x-bitbucket-event",
            # Slack
            "x-slack-signature",
            "x-slack-request-timestamp",
            # SendGrid
            "x-sendgrid-event-webhook-signature",
            # PayPal
            "x-paypal-transmission-sig",
            # Generic webhook standards
            "webhook-signature",
            "webhook-id",
            "webhook-timestamp",
        ),
        response_headers=(),
        path_patterns=(
            "/webhook",
            "/webhooks",
            "/hook",
            "/hooks",
            "/callback",
            "/event",
            "/events",
        ),
        url_param_names=(),
        body_patterns=(),
    ),

    "jsonrpc": ApiSignature(
        content_types=(
            "application/json-rpc",
            "application/json",              # JSON-RPC is often served as plain JSON
        ),
        request_headers=(),
        response_headers=(),
        path_patterns=(
            "/rpc/",
            "/jsonrpc/",
            "/json-rpc/",
            "/json_rpc/",
        ),
        url_param_names=(),
        body_patterns=(
            '"jsonrpc"',                     # JSON-RPC 2.0 mandatory version field — unique to this protocol
            # '"method"' and '"id"' are intentionally absent: both are ubiquitous
            # in generic REST responses and cause false positives on any JSON body
            # that has a "method" or "id" key. "jsonrpc" alone is sufficient.
        ),
    ),

    "odata": ApiSignature(
        content_types=(
            "application/json",
            "application/atom+xml",          # OData v3 Atom feed format
            "application/xml",
        ),
        request_headers=(),
        response_headers=(
            "odata-version",                 # present in all OData v4 responses
            "dataserviceversion",            # OData v1-v3 equivalent
        ),
        path_patterns=(
            "/odata/",
            "/$metadata",                    # OData service document endpoint
        ),
        url_param_names=(
            "$filter",                       # OData system query options
            "$select",
            "$expand",
            "$orderby",
            "$top",
            "$skip",
            "$count",
            "$format",
        ),
        body_patterns=(
            '"@odata.context"',             # OData JSON response envelope
            '"odata.metadata"',              # OData v3 JSON verbose
        ),
    ),
}


# ---------------------------------------------------------------------------
# Section 3 — Authentication detection signatures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthSignature:
    """
    Collection of detection signals for a single authentication mechanism.

    All fields are tuples of lowercase strings. core.analyzer checks observed
    request and response attributes against these tuples in all scan modes
    (active, passive, and spider). Auth detection is not passive-only.

    Attributes:
        auth_header_prefixes (tuple[str, ...]): Case-insensitive prefix values
            for the Authorization request header (e.g. 'basic ', 'bearer ').
        request_header_names (tuple[str, ...]): Specific request header names
            (lowercase) whose presence signals this auth type (e.g. 'x-api-key').
        response_header_names (tuple[str, ...]): Response header names
            (lowercase) that confirm or challenge this auth type.
        url_param_names (tuple[str, ...]): URL query parameter names
            (lowercase) that carry credentials or tokens.
        cookie_name_patterns (tuple[str, ...]): Lowercase substrings matched
            against Set-Cookie / Cookie header names.
    """

    auth_header_prefixes: tuple[str, ...]
    request_header_names: tuple[str, ...]
    response_header_names: tuple[str, ...]
    url_param_names: tuple[str, ...]
    cookie_name_patterns: tuple[str, ...]


AUTH_SIGNATURES: dict[str, AuthSignature] = {

    "basic": AuthSignature(
        auth_header_prefixes=("basic ",),
        request_header_names=(),
        response_header_names=(
            "www-authenticate",              # 401 response will contain 'Basic realm=...'
        ),
        url_param_names=(),
        cookie_name_patterns=(),
    ),

    "apikey": AuthSignature(
        auth_header_prefixes=(),
        request_header_names=(
            "x-api-key",
            "x-api-key",                    # capitalisation variant normalised to lowercase
            "api-key",
            "x-auth-token",
            "x-rapidapi-key",               # RapidAPI marketplace
            "x-mashape-key",                # Mashape / RapidAPI legacy
            "x-ibm-client-id",              # IBM API Connect
            "apikey",                        # non-hyphenated variant
            "token",                         # generic token header
        ),
        response_header_names=(),
        url_param_names=(
            "api_key",
            "apikey",
            "key",
            "token",
            "access_token",
            "auth",
            "api_token",
            "client_id",
            "client_secret",                 # never safe in URL — always CRITICAL
        ),
        cookie_name_patterns=(),
    ),

    "bearer": AuthSignature(
        auth_header_prefixes=("bearer ",),
        request_header_names=(),
        response_header_names=(
            "www-authenticate",             # 'Bearer realm=...' on 401
        ),
        url_param_names=(
            "access_token",                 # OAuth 2.0 token in URL (discouraged by RFC 6750)
        ),
        cookie_name_patterns=(),
    ),

    "oauth2": AuthSignature(
        auth_header_prefixes=("bearer ",),  # OAuth 2.0 bearer token in Authorization header
        request_header_names=(),
        response_header_names=(
            "www-authenticate",             # 'Bearer realm=...' on 401
            "x-oauth-scopes",              # granted scopes exposed by resource server
            "x-accepted-oauth-scopes",
        ),
        url_param_names=(
            "code",                         # authorization code flow callback
            "state",
            "access_token",
        ),
        cookie_name_patterns=(),
    ),

    "hmac": AuthSignature(
        auth_header_prefixes=("hmac ",),
        request_header_names=(
            "x-hub-signature",              # GitHub webhook HMAC-SHA1 (legacy)
            "x-hub-signature-256",          # GitHub webhook HMAC-SHA256 (current)
            "x-signature",
            "x-request-signature",
        ),
        response_header_names=(),
        url_param_names=(),
        cookie_name_patterns=(),
    ),

    "mtls": AuthSignature(
        auth_header_prefixes=(),
        request_header_names=(
            "x-client-certificate",         # forwarded by TLS-terminating reverse proxy
            "x-forwarded-client-cert",      # Envoy / Istio SPIFFE cert header
            "x-ssl-client-cert",            # nginx $ssl_client_cert forwarding
        ),
        response_header_names=(
            "x-client-certificate",
            "x-forwarded-client-cert",
            "x-ssl-client-cert",
        ),
        url_param_names=(),
        cookie_name_patterns=(),
    ),

    "session": AuthSignature(
        auth_header_prefixes=(),
        request_header_names=(),
        response_header_names=(),
        url_param_names=(),
        cookie_name_patterns=(
            "session",                      # generic session cookie name
            "sessionid",                    # Django default
            "phpsessid",                    # PHP default
            "jsessionid",                   # Java EE / Tomcat default
            "auth",                         # common auth cookie prefix
            "connect.sid",                  # Express.js session
            "asp.net_sessionid",            # ASP.NET
        ),
    ),
}


# ---------------------------------------------------------------------------
# Section 4 — Authentication misconfiguration security flags
# ---------------------------------------------------------------------------

class AuthSecurityFlag(NamedTuple):
    """
    Definition of a single authentication misconfiguration that Sentry flags.

    Attributes:
        description (str): Human-readable explanation of the misconfiguration.
        severity (str): Impact level — 'CRITICAL', 'HIGH', 'MEDIUM', or 'WARN'.
        remediation (str): Concise fix recommendation.
    """

    description: str
    severity: str
    remediation: str


# Keys are stable identifiers referenced in core.analyzer and report output.
AUTH_SECURITY_FLAGS: dict[str, AuthSecurityFlag] = {

    # Basic auth
    "basic_over_http": AuthSecurityFlag(
        description="Basic Auth credentials sent over unencrypted HTTP",
        severity="CRITICAL",
        remediation="Enforce HTTPS and add HSTS before allowing Basic Auth",
    ),
    "basic_in_url": AuthSecurityFlag(
        description="Basic Auth credentials embedded in URL (user:pass@host)",
        severity="CRITICAL",
        remediation="Remove credentials from URL; use Authorization header only",
    ),

    # API key
    "apikey_in_url": AuthSecurityFlag(
        description="API key transmitted as a URL query parameter",
        severity="HIGH",
        remediation="Move the API key to a request header (X-API-Key) instead",
    ),
    "apikey_over_http": AuthSecurityFlag(
        description="API key transmitted over unencrypted HTTP",
        severity="CRITICAL",
        remediation="Enforce HTTPS before sending any API keys",
    ),

    # JWT / Bearer
    "jwt_alg_none": AuthSecurityFlag(
        description='JWT uses alg:"none" — signature verification is bypassed',
        severity="CRITICAL",
        remediation='Reject any JWT with alg:"none"; require RS256 or ES256',
    ),
    "jwt_no_expiry": AuthSecurityFlag(
        description="JWT has no exp claim — token never expires",
        severity="WARN",
        remediation="Always set an exp claim; use short-lived tokens with refresh",
    ),
    "bearer_over_http": AuthSecurityFlag(
        description="Bearer token transmitted over unencrypted HTTP",
        severity="CRITICAL",
        remediation="Enforce HTTPS and add HSTS; tokens in transit must be encrypted",
    ),

    # HMAC
    "hmac_sha1": AuthSecurityFlag(
        description="HMAC signature uses SHA-1 which has known collision weaknesses",
        severity="WARN",
        remediation="Upgrade to HMAC-SHA256 (X-Hub-Signature-256 or equivalent)",
    ),

    # Cookie / session
    "cookie_missing_secure": AuthSecurityFlag(
        description="Session/auth cookie missing the Secure flag",
        severity="HIGH",
        remediation="Add Secure flag so cookie is only sent over HTTPS connections",
    ),
    "cookie_missing_httponly": AuthSecurityFlag(
        description="Session/auth cookie missing the HttpOnly flag",
        severity="HIGH",
        remediation="Add HttpOnly flag to prevent JavaScript access to session cookie",
    ),
    "cookie_missing_samesite": AuthSecurityFlag(
        description="Session/auth cookie missing the SameSite attribute",
        severity="MEDIUM",
        remediation="Set SameSite=Strict or SameSite=Lax to mitigate CSRF",
    ),

    # mTLS
    "mtls_http_fallback": AuthSecurityFlag(
        description="mTLS endpoint accessible over plain HTTP without client certificate",
        severity="HIGH",
        remediation="Reject all non-TLS connections at the load balancer level",
    ),

    # CORS
    "cors_wildcard_origin": AuthSecurityFlag(
        description="Access-Control-Allow-Origin: * permits any cross-origin request",
        severity="MEDIUM",
        remediation="Restrict to an explicit whitelist of trusted origins",
    ),
    "cors_wildcard_with_credentials": AuthSecurityFlag(
        description="Wildcard CORS origin combined with Allow-Credentials — broken policy",
        severity="HIGH",
        remediation="Use an explicit origin whitelist when Allow-Credentials is required",
    ),
    "cors_reflected_origin": AuthSecurityFlag(
        description="Server blindly reflects the request Origin in Access-Control-Allow-Origin",
        severity="HIGH",
        remediation="Validate Origin against an explicit whitelist; never reflect blindly",
    ),
    "cors_reflected_origin_with_credentials": AuthSecurityFlag(
        description="Reflected origin with Allow-Credentials: true — any site can make authenticated requests",
        severity="CRITICAL",
        remediation="Implement strict origin whitelist and never combine reflected origin with credentials",
    ),
    "cors_missing_vary_origin": AuthSecurityFlag(
        description="CORS response missing Vary: Origin — cached response may leak to wrong origins",
        severity="MEDIUM",
        remediation="Add Vary: Origin to every response that sets Access-Control-Allow-Origin",
    ),
}
