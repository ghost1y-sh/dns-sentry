#!/usr/bin/env python3
"""Subdomain length check for detecting DNS tunneling."""
class LengthCheck:
    """Analyze subdomain length for DNS tunneling indicators.
    DNS tunneling encodes data in subdomain labels, producing
    unusually long queries. Normal subdomains are short ('www',
    'mail', 'api'). Tunneled subdomains look like
    'a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5.evil.com'.
    Scoring:
        length < 15  -> 0 points (normal)
        length 15-25 -> 5 points (unusual)
        length 25-40 -> 12 points (suspicious)
        length > 40  -> 20 points (likely tunneling)
    """
    max_score = 20
    def run(self, domain, subdomain):
        """Run length analysis on the subdomain.
        Args:
            domain: Full domain string
            subdomain: Subdomain portion to analyze
        Returns:
            dict with name, score, flagged, detail, and length value
        """
        length = len(subdomain)
        if length > 40:
            score = 20
            detail = f"Very long subdomain ({length} chars) - likely DNS tunneling"
        elif length > 25:
            score = 12
            detail = f"Long subdomain ({length} chars) - suspicious"
        elif length > 15:
            score = 5
            detail = f"Moderately long subdomain ({length} chars) - unusual"
        else:
            score = 0
            detail = f"Normal length ({length} chars)"
        return {
            "name": "Subdomain Length",
            "score": score,
            "flagged": score >= 12,
            "detail": detail,
            "length": length,
        }