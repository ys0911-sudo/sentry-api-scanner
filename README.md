# Sentry

**Silent API security header scanner.** *Sentry watches your APIs so attackers can't.*

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)

Sentry inspects HTTP API endpoints for missing or misconfigured security
headers, weak authentication transport, and CORS mistakes — then grades each
endpoint and writes a structured report. It detects the API protocol
(REST, GraphQL, SOAP, gRPC, Webhook, JSON-RPC, OData) and applies the rules that
actually apply to that type.

Built by Yash Saran as part of an MSc in Cybersecurity at NFSU.

---

## Features

- **Two scan modes** — drive a list of URLs directly (*active*), or capture real
  browser traffic through a local proxy (*passive*).
- **Protocol-aware** — identifies REST / GraphQL / SOAP / gRPC / Webhook /
  JSON-RPC / OData and skips rules that don't apply (e.g. CSP on gRPC).
- **Header analysis** — checks recommended headers (HSTS, CSP, X-Frame-Options,
  …) and flags disclosure headers (Server, X-Powered-By, X-AspNet-Version),
  including value-quality checks (short HSTS max-age, unsafe CSP directives).
- **Auth & transport checks** — Basic, Bearer/JWT (decodes claims, flags
  `alg:none` and missing `exp`), API keys, HMAC, mTLS, session cookies, OAuth 2.0
  — with precise URL-parameter detection that won't cry wolf over `?page=2`.
- **CORS misconfiguration detection** — wildcard, reflected origin, and the
  dangerous credentials combinations.
- **Concurrent active scanning** with retries and polite backoff under rate limits.
- **Reports** in plain text, JSON, self-contained HTML, and PDF.

---

## Why Sentry

Most API security tools expect you to know your endpoints in advance, run a heavy
Java desktop suite, or pay for a SaaS subscription. Sentry takes a narrower remit
and does it from one pip-installed command:

| Capability                       | Sentry | Burp Suite | ZAP | StackHawk |
|----------------------------------|--------|------------|-----|-----------|
| Passive browser capture          | yes    | yes        | yes | no        |
| API protocol auto-detection      | yes    | no         | no  | no        |
| Per-protocol header rules        | yes    | no         | no  | no        |
| Auth misconfiguration detection  | yes    | manual     | no  | no        |
| Single-command install via pip   | yes    | no         | no  | no        |
| Free and open source             | yes    | no         | yes | no        |
| No Java, no Docker required      | yes    | no         | no  | no        |

Sentry is not a replacement for a full DAST suite — it is a focused, scriptable
check for the header, transport, auth, and CORS layer that those suites treat as
an afterthought.

---

## Requirements

- Python 3.11 or higher
- Linux (Ubuntu 20.04+, Kali, Debian 10+); active mode also runs anywhere CPython does
- Active mode works on headless servers with no display
- Passive mode requires a graphical environment (X11 or Wayland) and enough RAM
  to run Chromium (~2 GB free recommended)

---

## Installation

### pip

```bash
pip install sentry-api-scanner
```

`sentryscan --active` works immediately after install on any system, including
headless servers.

`sentryscan --passive` is registered only on systems where a graphical
environment is detected at install time. On a headless host the flag does not
exist at all — it is absent from `--help` rather than failing at runtime.

Optional — pre-download Chromium before the first passive scan (saves ~1 minute
on first use; a no-op on headless machines):

```bash
sentry-setup
```

### Kali / Debian

Install via `pip` today — it works the same on Kali and Debian as anywhere else.
A native `.deb` package is on the [roadmap](#roadmap) but is not published yet.

---

## Usage

### Active mode

Sends requests directly to the URLs you provide. Available everywhere, including
headless servers. For each endpoint Sentry sends a `GET`, an `OPTIONS` preflight
(to surface CORS issues), and — only when the path already looks like GraphQL or
JSON-RPC — a read-only POST probe (GraphQL introspection / JSON-RPC
`rpc.discover`) to confirm the type. No other endpoint ever receives a POST, so
the scan stays side-effect free. URLs are scanned concurrently with automatic
retries that honour `Retry-After`.

```bash
# Single endpoint (scheme optional — https:// is assumed)
sentryscan --active --url api.github.com/v1/users

# Bulk scan from a file, 10 at a time
sentryscan --active --file urls.txt --concurrency 10

# JSON output
sentryscan --active --url https://api.example.com --output json

# Save to a custom directory
sentryscan --active --file urls.txt --save /tmp/reports

# Skip TLS verification for internal self-signed APIs
sentryscan --active --url https://internal.api.corp --insecure

# Disable POST probing entirely
sentryscan --active --url https://api.example.com/graphql --no-probe
```

### Passive mode (desktop only)

Opens Chromium routed through a local interception proxy, lets you browse the
target by hand, and analyses every API response the browser makes — including
authenticated and dynamically-loaded calls a URL list would miss. Results appear
when you close the window or the `--timeout` elapses.

> **Note:** passive mode disables TLS certificate validation for the browser
> session so it can inspect HTTPS traffic. Do not log into unrelated personal
> accounts while a passive scan is running.

```bash
# Opens Chromium — browse normally — results on close
sentryscan --passive --url https://app.example.com

# Extend the session timeout to two minutes
sentryscan --passive --url https://app.example.com --timeout 120

# JSON output
sentryscan --passive --url https://app.example.com --output json
```

### Example output

```
Sentry -- Active Scan

--- https://api.github.com ---
API Type: rest   Score: 85/100   Grade: A

Security Headers
  Header                      Status   Severity   Detail
  Strict-Transport-Security   [PASS]   HIGH       max-age=31536000; includeSubdomains; preload
  Content-Security-Policy     [PASS]   HIGH       default-src 'none'
  X-Frame-Options             [PASS]   MEDIUM     deny
  X-Content-Type-Options      [PASS]   MEDIUM     nosniff
  Permissions-Policy          [FAIL]   LOW        Restricts browser feature access
  Cache-Control               [WARN]   MEDIUM     public, max-age=60, s-maxage=60
  Server                      [FAIL]   LOW        github.com

Authentication
  Mechanism   Severity   Detail
  cors        MEDIUM     [WARN] Access-Control-Allow-Origin: * permits any cross-origin request

Summary
  Scanned: 1 URL(s)   Errors: 0   Avg Score: 85/100
  [!] 1 URL(s) have FAIL findings

Report saved to: ~/sentry-reports/2026-06-01_14-30-22_api.github.com/
```

---

## Options

| Option | Description |
|---|---|
| `--active` | Scan URLs directly (default mode). |
| `--passive` | Capture browser traffic (desktop only). |
| `-u, --url URL` | Single target URL. |
| `-f, --file FILE` | File with one URL per line (`#` comments allowed). |
| `-o, --output` | `table` (default), `json`, `html`, or `pdf`. |
| `-s, --save DIR` | Override the report save location. |
| `-t, --timeout N` | Per-request timeout (seconds). In passive mode, total session length. |
| `-c, --concurrency N` | URLs scanned in parallel in active mode (default 5). |
| `--retries N` | Retry attempts for transient failures (default 2). |
| `--probe / --no-probe` | Read-only POST probing of GraphQL/JSON-RPC paths (default on). |
| `-k, --insecure` | Skip TLS certificate verification (e.g. internal self-signed APIs). |
| `--user-agent STRING` | Override the request User-Agent. |
| `-v, --verbose` | Print each request as it is made. |
| `-V, --version` | Show version and exit. |

---

## What Sentry checks

### Missing security headers

| Header                    | Severity |
|---------------------------|----------|
| Strict-Transport-Security | HIGH     |
| Content-Security-Policy   | HIGH     |
| Cache-Control             | MEDIUM   |
| X-Frame-Options           | MEDIUM   |
| X-Content-Type-Options    | MEDIUM   |
| Referrer-Policy           | LOW      |
| Permissions-Policy        | LOW      |

Present-but-weak values are reported as WARN rather than FAIL — for example an
HSTS `max-age` under one year, a CSP with `unsafe-inline`, or a `Cache-Control`
that allows storage of sensitive API responses.

### Harmful disclosure headers

| Header           | Severity |
|------------------|----------|
| X-AspNet-Version | HIGH     |
| Server           | LOW      |
| X-Powered-By     | LOW      |

### CORS misconfigurations

| Pattern                                   | Severity |
|-------------------------------------------|----------|
| `Access-Control-Allow-Origin: *`          | MEDIUM   |
| Wildcard + `Allow-Credentials: true`      | HIGH     |
| Reflected arbitrary origin                | HIGH     |
| Reflected origin + credentials            | CRITICAL |
| Missing `Vary: Origin` on a dynamic origin| MEDIUM   |

In active mode the `OPTIONS` preflight is sent with a deliberately invalid probe
origin, so any reflection of it is an unambiguous blind-reflection bug.

### Protocol detection

REST, GraphQL, SOAP, gRPC, Webhook, JSON-RPC, OData.

Detection uses confidence scoring across URL path patterns, Content-Type headers,
request and response body signatures, and vendor-specific headers. A minimum of
25 confidence points is required before a specific protocol is claimed; otherwise
the endpoint falls back to REST at 5 points, or UNKNOWN if there are no signals
at all.

GraphQL and JSON-RPC are best detected with POST probing enabled (the default),
since they reject `GET`. gRPC relies on HTTP/2 trailers that the active scanner
cannot observe, so gRPC is realistically only identified in passive mode.

### Authentication checks

| Method     | Checks performed |
|------------|------------------|
| Basic Auth | Flags credentials sent over HTTP; flags credentials embedded in the URL |
| API key    | Flags keys passed as URL parameters; flags keys sent over HTTP |
| Bearer/JWT | Decodes header and payload; flags `alg:none`; flags a missing `exp` claim |
| HMAC       | Flags SHA-1 use (`X-Hub-Signature` with no `-256` counterpart) |
| Session    | Checks the `Secure`, `HttpOnly`, and `SameSite` cookie attributes |
| mTLS       | Detects forwarded client-certificate headers (proxy/Envoy/nginx) |
| OAuth 2.0  | Detects bearer tokens alongside OAuth scope response headers |

URL-parameter detection is value-aware: a credential-shaped value in `?key=` or
`?token=` is flagged, but ordinary values such as `?key=name` or `?token=1` are
not. A public OAuth `client_id` is never treated as a leaked secret.

---

## Scoring

Each endpoint starts at 100. Points are deducted per missing or weak header,
weighted by severity, and per disclosure header present. The score is floored at
0 and mapped to a letter grade.

| Condition               | Deduction |
|-------------------------|-----------|
| Missing HIGH header     | 20        |
| Missing MEDIUM header   | 10        |
| Missing LOW header      | 5         |
| Present-but-weak header | half of the above |
| Disclosure header present | 5 each  |

| Score  | Grade |
|--------|-------|
| 80–100 | A     |
| 65–79  | B     |
| 50–64  | C     |
| 30–49  | D     |
| 0–29   | F     |

Headers are excluded from scoring where they do not apply: gRPC endpoints are not
penalised for missing Content-Security-Policy or X-Frame-Options.

---

## Reports

Every scan auto-saves to a timestamped directory:

```
~/sentry-reports/{YYYY-MM-DD}_{HH-MM-SS}_{target}/
├── report.json    structured findings per endpoint
└── report.txt     plain-text mirror of the terminal output
```

`report.html` or `report.pdf` is written in addition when `--output html` or
`--output pdf` is used. Saving always happens; `--output` only controls the
terminal format and which extra file is written. Use `--save DIR` to override the
location.

The JSON report is structured for CI/CD pipelines and for attaching as evidence
to a bug-bounty submission.

---

## Roadmap

- Docker image
- Native Debian `.deb` package
- CI/CD integration (JSON output plus a GitHub Actions workflow)
- v1.0.0 stable release

---

## Responsible use

Sentry is built for authorised security testing only. Scan APIs you own or have
explicit written permission to test.

When testing third-party APIs under a bug-bounty program, follow responsible
disclosure: report findings privately and allow remediation time before any
public disclosure.

---

## Contributing

Issues and pull requests are welcome. Please open an issue before submitting a
large pull request so the change can be discussed first.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built by Yash Saran — MSc Cybersecurity, Pursuing M.Tech Artificial Intelligence & Data Science (Specialization in Cybersecurity), NFSU, Gandhinagar*
