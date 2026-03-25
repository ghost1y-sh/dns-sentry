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
    Also detects hex-encoded subdomains which may have low entropy
    due to repeated characters but are still machine-generated.
    Scoring:
        entropy < 2.5  -> 0 points (normal)
        entropy 2.5-3.5 -> 10 points (slightly unusual)
        entropy 3.5-4.0 -> 25 points (suspicious)
        entropy > 4.0  -> 35 points (likely DGA)
        hex string > 6 chars -> minimum 25 points
    """
    max_score = 35
    HEX_CHARS = set("0123456789abcdef")
    def run(self, domain, subdomain):
        """Run entropy analysis on the subdomain.
        Args:
            domain: Full domain string
            subdomain: Subdomain portion to analyze
        Returns:
            dict with name, score, flagged, detail, and raw entropy value
        """
        entropy = self._shannon_entropy(subdomain)
        is_hex = self._is_hex_string(subdomain)
        if entropy > 4.0:
            score = 35
            detail = f"Very high entropy ({entropy:.2f}) - likely algorithmically generated"
        elif entropy > 3.5:
            score = 25
            detail = f"High entropy ({entropy:.2f}) - suspicious randomness"
        elif entropy > 2.5:
            score = 10
            detail = f"Moderate entropy ({entropy:.2f}) - slightly unusual"
        else:
            score = 0
            detail = f"Normal entropy ({entropy:.2f})"
        #Hex override - hex strings are machine-generated regardless of entropy
        if is_hex and score < 25:
            score = 25
            detail = f"Hex-encoded subdomain detected ({entropy:.2f} entropy) - likely machine-generated"
        return {
            "name": "Shannon Entropy",
            "score": score,
            "flagged": score >= 25,
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
    def _is_hex_string(self, text):
        """Check if a string looks like hex-encoded data.
        Returns True if the string is longer than 6 characters and
        contains only hex characters (0-9, a-f). Short strings like
        'dead' or 'cafe' are common words and shouldn't trigger.
        """
        if len(text) <= 6:
            return False
        return all(c in self.HEX_CHARS for c in text.lower())