#!/usr/bin/env python3

"""Shannon entropy check for detecting DGA-generated domains."""

import math
from collections import Counter


class EntropyCheck:
    """Calculate Shannon entropy of the subdomain portion.

    High entropy (randomness) suggests the domain was algorithmically
    generated (DGA) rather than chosen by a human. Legitimate domains
    like 'mail' or 'login' have low entropy. DGA domains like
    'a3f9b2c1d4e5' have high entropy.

    Scoring:
        entropy < 3.0  -> 0 points (normal)
        entropy 3.0-3.5 -> 5 points (slightly unusual)
        entropy 3.5-4.0 -> 15 points (suspicious)
        entropy > 4.0  -> 25 points (likely DGA)
    """

    max_score = 25

    def run(self, domain, subdomain):
        """Run entropy analysis on the subdomain.

        Args:
            domain: Full domain string
            subdomain: Subdomain portion to analyze

        Returns:
            dict with name, score, flagged, detail, and raw entropy value
        """
        entropy = self._shannon_entropy(subdomain)

        if entropy > 4.0:
            score = 25
            detail = f"Very high entropy ({entropy:.2f}) - likely algorithmically generated"
        elif entropy > 3.5:
            score = 15
            detail = f"High entropy ({entropy:.2f}) - suspicious randomness"
        elif entropy > 3.0:
            score = 5
            detail = f"Moderate entropy ({entropy:.2f}) - slightly unusual"
        else:
            score = 0
            detail = f"Normal entropy ({entropy:.2f})"

        return {
            "name": "Shannon Entropy",
            "score": score,
            "flagged": score >= 15,
            "detail": detail,
            "entropy": round(entropy, 4),
        }

    def _shannon_entropy(self, text):
        """Calculate Shannon entropy of a string.

        Shannon entropy measures the average amount of information per
        character. Random strings have high entropy, structured strings
        have low entropy.

        H = -sum(p(x) * log2(p(x))) for each unique character x
        """
        if not text:
            return 0.0

        counts = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy