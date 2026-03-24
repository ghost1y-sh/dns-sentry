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
        #Correlation bonus - multiple independent flags are stronger together
        flagged_count = sum(1 for r in check_results if r["flagged"])
        if flagged_count >= 3:
            total_score = int(total_score * 1.5)
        elif flagged_count >= 2:
            total_score = int(total_score * 1.3)
        #Normalize to 0-100 scale - exclude VT max if VT was skipped
        max_possible = sum(
            c.max_score for c in self.checks
            if not (isinstance(c, VirusTotalCheck) and not c.api_key)
        )
        risk_score = min(int((total_score / max_possible) * 100), 100) if max_possible > 0 else 0
        risk_level = self._score_to_level(risk_score)
        #VT override - vendor detections force minimum risk levels
        vt_result = next((r for r in check_results if r["name"] == "VirusTotal Reputation"), None)
        if vt_result and vt_result["detections"]:
            if vt_result["detections"] >= 10 and risk_level not in ("critical",):
                risk_level = "critical"
                risk_score = max(risk_score, 70)
            elif vt_result["detections"] >= 4 and risk_level not in ("critical", "high"):
                risk_level = "high"
                risk_score = max(risk_score, 40)
        return {
            "domain": domain,
            "subdomain": subdomain,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "checks": check_results,
        }
    def _score_to_level(self, score):
        """Convert a numeric score to a risk level label."""
        if score >= 70:
            return "critical"
        elif score >= 40:
            return "high"
        elif score >= 20:
            return "medium"
        else:
            return "low"