#!/usr/bin/env python3

"""Domain analyzer - orchestrates all checks and produces a risk score."""

from app.checks.entropy import EntropyCheck
from app.checks.length import LengthCheck
from app.checks.ratio import ConsonantVowelCheck
from app.checks.age import DomainAgeCheck
from app.checks.virustotal import VirusTotalCheck


class DomainAnalyzer:
    """Runs a domain through a pipeline of security checks and scores it."""

    def __init__(self, vt_api_key=None, cache=None):
        self.cache = cache
        self.checks = [
            EntropyCheck(),
            LengthCheck(),
            ConsonantVowelCheck(),
            DomainAgeCheck(cache=cache),
            VirusTotalCheck(api_key=vt_api_key, cache=cache),
        ]

    def analyze(self, domain):
        """Run all checks against a domain and return scored results.

        Args:
            domain: The domain name to analyze (e.g., 'a3f9b2c1.evil.com')

        Returns:
            dict with domain, risk_score, risk_level, and individual check results
        """
        domain = domain.strip().lower()

        #Extract the subdomain portion for analysis
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
        else:
            subdomain = parts[0]

        check_results = []
        total_score = 0

        for check in self.checks:
            result = check.run(domain, subdomain)
            check_results.append(result)
            total_score += result["score"]

        #Normalize to 0-100 scale
        max_possible = sum(c.max_score for c in self.checks)
        risk_score = min(int((total_score / max_possible) * 100), 100) if max_possible > 0 else 0

        risk_level = self._score_to_level(risk_score)

        return {
            "domain": domain,
            "subdomain": subdomain,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "checks": check_results,
        }

    def _score_to_level(self, score):
        """Convert a numeric score to a risk level label."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"