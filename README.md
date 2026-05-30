# Sentry

**Silent API security header scanner** — *Sentry watches your APIs so attackers can't.*

Built by Yash Saran as part of MSc Cybersecurity at NFSU.

## Installation

```bash
pip install sentry-api-scanner
playwright install chromium
```

Or via apt (Kali/Debian):
```bash
sudo dpkg -i sentry_0.1.0_all.deb
```

## Usage

```bash
# Passive mode — intercepts real browser traffic
sentry --passive

# Active mode — scan a single URL
sentry --active -u https://api.example.com/v1/users

# Active mode — scan a list of URLs
sentry --active -f urls.txt

# Spider mode — auto-discover and scan APIs from a base URL
sentry --spider -u https://api.github.com

# Output formats
sentry --active -f urls.txt --output html
sentry --passive --output json
sentry --passive --output pdf

# Save report to file
sentry --active -f urls.txt --save report.json

# Force API type
sentry --active -u api.example.com --type graphql
```

## What Sentry checks

**Missing headers (bad):** Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cache-Control

**Dangerous headers (bad):** Server, X-Powered-By, X-AspNet-Version

**API types detected:** REST, GraphQL, SOAP, gRPC, Webhook, JSON-RPC

## Scoring

`score = (present_recommended / total_recommended × 100) − (harmful_count × 5)`

- 80+ → GOOD
- 50–79 → MODERATE
- below 50 → POOR

## License

MIT — see [LICENSE](LICENSE)
