# dns-sentry

DNS suspicious domain analyzer. Scores domains for DGA patterns, DNS tunneling indicators, domain age, and threat intelligence reputation.

Runs as a CLI tool, Flask web service, or Kubernetes deployment. Implements Shannon entropy analysis, WHOIS age lookups, VirusTotal API integration, correlation scoring, and authoritative signal overrides.

**Live demo:** [https://dns-sentry.com](https://dns-sentry.com)

## What It Does

dns-sentry runs domains through five detection checks and produces a normalized risk score (0-100):

| Check | Detects | Method |
|-------|---------|--------|
| Shannon Entropy | DGA-generated domains | Measures character randomness in subdomain |
| Subdomain Length | DNS tunneling | Flags unusually long subdomains encoding data |
| Consonant/Vowel Ratio | Generated strings | Human words have predictable letter ratios |
| Domain Age (WHOIS) | Newly registered domains | Attackers register domains right before campaigns |
| VirusTotal Reputation | Known malicious domains | Aggregates verdicts from 70+ security vendors |

Additional detection features:

- **Hex string detection** — identifies hex-encoded subdomains (e.g., `0bd8eee3e8ba`) that may have low entropy but are clearly machine-generated
- **Correlation scoring** — multiple independent flags multiply the composite score (1.3x for 2 flags, 1.5x for 3+)
- **VirusTotal override floors** — vendor detections force minimum risk levels regardless of composite score (1+ = medium, 2+ = high, 10+ = critical)
- **Common subdomain whitelist** — skips false positives on `www`, `ftp`, `mx`, `cdn`, etc.

## Quick Start

### CLI

```bash
git clone https://github.com/ghost1y-sh/dns-sentry.git
cd dns-sentry
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your VirusTotal API key
python3 main.py -d suspicious-domain.com
```

Analyze multiple domains:
```bash
python3 main.py -d evil.com -d sketchy.xyz -d google.com
```

From a file:
```bash
python3 main.py -f domains.txt -o results.json
```

### Docker Compose

```bash
git clone https://github.com/ghost1y-sh/dns-sentry.git
cd dns-sentry
cp .env.example .env   # add your VirusTotal API key
docker compose up -d --build
```

Open `http://localhost` in your browser.

### Kubernetes

```bash
git clone https://github.com/ghost1y-sh/dns-sentry.git
cd dns-sentry
kubectl apply -f k8s/namespace.yaml
kubectl create secret generic dns-sentry-secrets \
  --namespace=dns-sentry \
  --from-literal=VT_API_KEY=your_key_here
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/web.yaml
kubectl apply -f k8s/nginx.yaml
```

Access at `http://<node-ip>:30080`.

### Pre-built Container Image

Multi-architecture image (amd64 + arm64) available on GitHub Container Registry:

```bash
docker pull ghcr.io/ghost1y-sh/dns-sentry:latest
```

## Architecture

```
nginx (reverse proxy, rate limiting)
  └── flask-api (gunicorn, 2 workers)
        └── redis (WHOIS + VT result caching)
```

Three containers on an isolated network. Only nginx exposes ports. Flask and Redis are internal and unreachable from outside.

## Scoring

### Weights

Scores are weighted by signal reliability:

| Check | Max Score | Weight Rationale |
|-------|-----------|-----------------|
| VirusTotal | 40 | Hardest signal — actual vendor detections |
| Entropy | 35 | Primary DGA indicator, pure math |
| Domain Age | 30 | Strong real-world indicator |
| Length | 20 | Good tunneling indicator |
| Ratio | 10 | Supporting signal, most false positives |

Total max: 135, normalized to 0-100.

### Risk Levels

| Score | Level |
|-------|-------|
| 0-19 | Low |
| 20-39 | Medium |
| 40-69 | High |
| 70-100 | Critical |

### Correlation Scoring

When multiple independent checks flag, the composite score is multiplied. Two flags = 1.3x, three or more = 1.5x. Independent signals confirming each other are exponentially more suspicious than any single indicator.

### VirusTotal Overrides

Vendor detections force minimum risk levels regardless of composite score. Any detection = minimum medium. Two or more = minimum high. Ten or more = minimum critical. Threat intelligence from multiple vendors is deterministic and should not be diluted by the composite score.

## API

### POST /api/analyze

```bash
curl -X POST http://localhost/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "a3f9b2c1d4e5.evil.com"]}'
```

Request: `{"domains": ["domain1", "domain2"]}` (max 50)

Response:
```json
{
  "results": [
    {
      "domain": "example.com",
      "subdomain": "example",
      "risk_score": 0,
      "risk_level": "low",
      "checks": [...]
    }
  ],
  "summary": {
    "total": 2, "critical": 0, "high": 0, "medium": 0, "low": 2
  }
}
```

### GET /api/health

```bash
curl http://localhost/api/health
```

Returns: `{"status": "healthy", "service": "dns-sentry"}`

## Configuration

All configuration via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| VT_API_KEY | No | empty | VirusTotal API key (free tier: 4 req/min, 500/day) |
| REDIS_HOST | No | localhost | Redis hostname (set to `redis` for Docker/k8s) |
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
│   ├── analyzer.py          ← Orchestrates checks, scoring, overrides
│   ├── cache.py             ← Redis caching layer
│   └── checks/
│       ├── entropy.py       ← Shannon entropy + hex detection
│       ├── length.py        ← Subdomain length analysis
│       ├── ratio.py         ← Consonant/vowel ratio
│       ├── age.py           ← WHOIS domain age
│       └── virustotal.py    ← VirusTotal API with rate limiting
├── templates/
│   └── index.html           ← Terminal-themed web UI
└── k8s/
    ├── namespace.yaml
    ├── secret.yaml.example
    ├── redis.yaml
    ├── web.yaml
    └── nginx.yaml
```

## Kubernetes Management

```bash
# Deploy
kubectl apply -f k8s/namespace.yaml
kubectl create secret generic dns-sentry-secrets \
  --namespace=dns-sentry \
  --from-literal=VT_API_KEY=your_key_here
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/web.yaml
kubectl apply -f k8s/nginx.yaml

# Check status
kubectl get pods -n dns-sentry
kubectl get pods -n dns-sentry -o wide
kubectl get all -n dns-sentry

# View logs
kubectl logs -n dns-sentry deployment/web
kubectl logs -n dns-sentry deployment/nginx
kubectl logs -n dns-sentry deployment/redis

# Restart a deployment
kubectl rollout restart deployment web -n dns-sentry

# Scale web replicas
kubectl scale deployment web -n dns-sentry --replicas=3

# Stop workloads (keep namespace and secret)
kubectl delete -f k8s/nginx.yaml
kubectl delete -f k8s/web.yaml
kubectl delete -f k8s/redis.yaml

# Full teardown (removes everything including secret)
kubectl delete namespace dns-sentry

# Update to new image version
kubectl set image deployment/web \
  web=ghcr.io/ghost1y-sh/dns-sentry:v1.1.0 -n dns-sentry
```

## Security

### Container Security
- Non-root `sentry` user inside the Flask container
- Flask and Redis on isolated Docker/Kubernetes network
- Only nginx exposes ports externally
- Read-only config mounts

### Network Security
- Rate limiting on analyze endpoint (protects VT API quota)
- Security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, HSTS
- VT API key stored as Kubernetes Secret or .env file, never committed to git

### Kubernetes Security
- API key stored as Kubernetes Secret, not in manifests
- Resource requests and limits on all containers
- Liveness and readiness probes on web pods
- Pods distributed across worker nodes for high availability

### Rate Limiting
- VirusTotal: 15-second delay between API calls (Python-level)
- nginx: 2 req/s on analyze endpoint with burst of 10
- nginx: 30 req/m on web UI

## Requirements

**CLI:** Python 3.10+

**Docker:** Docker Engine, Docker Compose v2

**Kubernetes:** kubectl, cluster with arm64 or amd64 nodes

**Optional:** VirusTotal API key (free at [virustotal.com](https://www.virustotal.com))

## License

MIT