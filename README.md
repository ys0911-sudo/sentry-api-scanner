# Sentry

**Silent API security header scanner** — *Sentry watches your APIs so attackers can't.*

Built by Yash Saran as part of MSc Cybersecurity at NFSU.

## Installation

```bash
pip install sentry-api-scanner
```

That's it. `sentryscan --active` works immediately after install on any system.
`sentryscan --passive` is available on desktop and auto-installs Chromium on first run.

**Optional:** run `sentry-setup` once to pre-download Chromium before your first
passive scan (saves ~1 minute on first use):

```bash
pip install sentry-api-scanner
sentry-setup   # optional — pre-warms Chromium; skipped automatically on headless
```

**Kali / Debian (.deb package — handles everything automatically):**
```bash
sudo dpkg -i sentry_0.1.0_all.deb
```

## Usage

```bash
# Active mode — scan a single URL directly
sentryscan --active --url https://api.example.com/v1/users

# Active mode — scan a list of URLs from a file
sentryscan --active --file urls.txt

# Active mode — emit JSON output to terminal
sentryscan --active --url https://api.example.com --output json

# Active mode — save report to a custom directory
sentryscan --active --file urls.txt --save /tmp/my-reports

# Active mode — skip SSL verification (e.g. internal APIs with self-signed certs)
sentryscan --active --url https://internal.api.corp --insecure

# Passive mode — intercept real browser traffic (desktop only)
# Opens Chromium, browse the target manually, results appear on close
sentryscan --passive --url https://app.example.com

# Passive mode — extend session to 2 minutes for thorough browsing
sentryscan --passive --url https://app.example.com --timeout 120

# Passive mode — emit results as JSON
sentryscan --passive --url https://app.example.com --output json
```

## What Sentry checks

**Missing headers (FAIL if absent):**

| Header | Severity |
|---|---|
| Strict-Transport-Security | HIGH |
| Content-Security-Policy | HIGH |
| Cache-Control | MEDIUM |
| X-Frame-Options | MEDIUM |
| X-Content-Type-Options | MEDIUM |
| Referrer-Policy | LOW |
| Permissions-Policy | LOW |

**Dangerous headers (FAIL if present):**

| Header | Severity |
|---|---|
| X-AspNet-Version | HIGH |
| Server | LOW |
| X-Powered-By | LOW |

**CORS misconfigurations detected:**
- `Access-Control-Allow-Origin: *` (MEDIUM)
- Wildcard origin + `Allow-Credentials: true` (HIGH)
- Reflected arbitrary origin (HIGH)
- Reflected origin + credentials (CRITICAL)
- Missing `Vary: Origin` (MEDIUM)

**Authentication mechanisms detected:**
Basic Auth, Bearer/JWT (decodes claims, checks `alg:none` and missing `exp`),
API Keys (headers + URL params), HMAC, mTLS, Session Cookies, OAuth 2.0

**API types detected:**
REST, GraphQL, SOAP, gRPC, Webhook, JSON-RPC, OData

## Scoring

Each endpoint is scored 0–100:
- Start at 100
- Deduct points per missing/weak header (weighted by severity)
- Deduct 5 points per harmful header present

| Score | Grade |
|---|---|
| 80–100 | A |
| 65–79 | B |
| 50–64 | C |
| 30–49 | D |
| 0–29 | F |

## Reports

Every scan auto-saves a report to `~/sentry-reports/{date}_{time}_{target}/`:
- `report.json` — structured data (score, grade, all findings per endpoint)
- `report.txt` — plain text mirror of terminal output

Use `--save DIR` to override the save location.

## License

MIT — see [LICENSE](LICENSE)
