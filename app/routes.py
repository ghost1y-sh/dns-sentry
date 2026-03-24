#!/usr/bin/env python3

"""Flask routes for dns-sentry web interface and API."""

from flask import Blueprint, request, jsonify, render_template, current_app
from app.analyzer import DomainAnalyzer
from app.cache import RedisCache

bp = Blueprint("main", __name__)


def get_analyzer():
    """Get a DomainAnalyzer instance with app config."""
    cache = None
    try:
        cache = RedisCache(
            host=current_app.config["REDIS_HOST"],
            port=current_app.config["REDIS_PORT"]
        )
    except Exception:
        pass

    return DomainAnalyzer(
        vt_api_key=current_app.config.get("VT_API_KEY"),
        cache=cache
    )


@bp.route("/")
def index():
    """Render the web UI."""
    return render_template("index.html")


@bp.route("/api/analyze", methods=["POST"])
def analyze():
    """Analyze one or more domains.

    Accepts JSON:
        {"domains": ["example.com", "xn--abc123.evil.com"]}

    Returns JSON:
        {"results": [...], "summary": {...}}
    """
    data = request.get_json()

    if not data or "domains" not in data:
        return jsonify({"error": "Missing 'domains' field in request body"}), 400

    domains = data["domains"]
    if not isinstance(domains, list) or len(domains) == 0:
        return jsonify({"error": "'domains' must be a non-empty list"}), 400

    if len(domains) > 50:
        return jsonify({"error": "Maximum 50 domains per request"}), 400

    analyzer = get_analyzer()
    results = []

    for domain in domains:
        domain = domain.strip()
        if domain:
            result = analyzer.analyze(domain)
            results.append(result)

    summary = {
        "total": len(results),
        "critical": len([r for r in results if r["risk_level"] == "critical"]),
        "high": len([r for r in results if r["risk_level"] == "high"]),
        "medium": len([r for r in results if r["risk_level"] == "medium"]),
        "low": len([r for r in results if r["risk_level"] == "low"]),
    }

    return jsonify({"results": results, "summary": summary})


@bp.route("/api/health")
def health():
    """Health check endpoint for Kubernetes probes."""
    return jsonify({"status": "healthy", "service": "dns-sentry"})