# dns-sentry

DNS suspicious domain analyzer. Scores domains for DGA patterns, DNS tunneling indicators, domain age, and threat intelligence reputation. Runs as a CLI tool or a Flask web service with Redis caching.

## What It Does

dns-sentry runs domains through five detection checks and produces a normalized risk score (0-100):

| Check | Detects | How |
|-------|---------|-----|
| Shannon Entropy | DGA-generated domains | Measures character randomness in subdomain |
| Subdomain Length | DNS tunneling | Flags unusually long subdomains encoding data |
| Consonant/Vowel Ratio | Generated strings | Human words have predictable letter ratios |
| Domain Age (WHOIS) | Newly registered domains | Attackers register domains right before campaigns |
| VirusTotal Reputation | Known malicious domains | Aggregates verdicts from 70+ security vendors |

Scoring uses weighted checks, correlation multipliers for multiple independent flags, and VirusTotal override floors to ensure vendor-flagged domains are never underreported.

## Quick Start

### CLI Mode

```bash
git clone https://github.com/ghost1y-sh/dns-sentry.git
cd dns-sentry
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # Add your VirusTotal API key
python3 main.py -d suspicious-domain.com
```

Analyze multiple domains:
```bash
python3 main.py -d evil.com -d sketchy.xyz -d google.com
```

From a file (one domain per line):
```bash
python3 main.py -f domains.txt -o results.json
```

### Web Service (Docker)

```bash
git clone https://github.com/ghost1y-sh/dns-sentry.git
cd dns-sentry
cp .env.example .env   # Add your VirusTotal API key
docker compose up -d --build
```

Open `http://localhost` in your browser.

### Web Service (Local Development)

```bash
python3 main.py --web
```

Flask dev server runs on `http://localhost:5000`.

## API

**POST /api/analyze**
```bash
curl -X POST http://localhost/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "a3f9b2c1d4e5.evil.com"]}'
```

Returns:
```json
{
  "results": [
    {
      "domain": "example.com",
      "risk_score": 0,
      "risk_level": "low",
      "checks": [...]
    }
  ],
  "summary": {
    "total": 2,
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 1
  }
}
```

**GET /api/health**
```bash
curl http://localhost/api/health
```

## Architecture

```
nginx (reverse proxy + rate limiting)
  └── flask-api (gunicorn, 2 workers)
        └── redis (WHOIS + VT result caching)
```

Three containers on an isolated Docker network. Only nginx exposes ports. Flask and Redis are internal.

## Scoring

Risk levels: **low** (0-19) | **medium** (20-39) | **high** (40-69) | **critical** (70-100)

Weights reflect signal reliability: VirusTotal (40) > Domain Age (30) > Entropy (35) > Length (20) > Ratio (10). Total max 135, normalized to 0-100.

**Correlation scoring:** When 2+ independent checks flag, the composite score is multiplied (1.3x for 2 flags, 1.5x for 3+). Multiple weak signals together are stronger than any single indicator.

**VirusTotal overrides:** 4+ vendor detections force a minimum of HIGH. 10+ force CRITICAL. Threat intelligence from multiple vendors is deterministic and should not be diluted by the composite score.

## Configuration

All configuration via environment variables (`.env` file):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| VT_API_KEY | No | empty | VirusTotal API key (free tier: 4 req/min, 500/day) |
| REDIS_HOST | No | localhost | Redis hostname (set to `redis` for Docker) |
| REDIS_PORT | No | 6379 | Redis port |

The tool works without a VirusTotal API key. VT checks are skipped gracefully and excluded from score normalization.

## Project Structure

```
dns-sentry/
├── main.py                  ← Entry point (CLI or web service)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── .env.example
├── app/
│   ├── __init__.py          ← Flask app factory
│   ├── routes.py            ← API + web UI endpoints
│   ├── analyzer.py          ← Orchestrates checks, scores results
│   ├── cache.py             ← Redis caching layer
│   └── checks/
│       ├── entropy.py       ← Shannon entropy (DGA detection)
│       ├── length.py        ← Subdomain length (tunneling detection)
│       ├── ratio.py         ← Consonant/vowel ratio
│       ├── age.py           ← WHOIS domain age
│       └── virustotal.py    ← VirusTotal API reputation
└── templates/
    └── index.html           ← Terminal-themed web UI
```

## Security

The Docker deployment includes:

- **Non-root container user** — Flask runs as an unprivileged `sentry` user
- **Network isolation** — Flask and Redis are on an internal Docker network, unreachable from outside
- **Rate limiting** — nginx limits the analyze endpoint to 10 requests/minute per IP to protect the VirusTotal API quota
- **Security headers** — X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- **Read-only config mount** — nginx.conf mounted as read-only

## Requirements

**CLI:** Python 3.10+, pip

**Docker:** Docker Engine, Docker Compose

**Optional:** VirusTotal API key (free at [virustotal.com](https://www.virustotal.com))

## License

MIT