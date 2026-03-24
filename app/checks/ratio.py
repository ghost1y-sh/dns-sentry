#!/usr/bin/env python3
"""Consonant-to-vowel ratio check for DGA detection."""
class ConsonantVowelCheck:
    """Analyze the consonant-to-vowel ratio in the subdomain.
    Human-chosen domain names follow natural language patterns with
    a mix of consonants and vowels. DGA domains are random and tend
    to have abnormal ratios - either heavily consonant (random hex
    like 'a3f9b2c1') or lacking the vowel distribution of real words.
    Scoring:
        ratio 1.0-4.0  -> 0 points (normal English-like)
        ratio 4.0-6.0  -> 5 points (unusual)
        ratio > 6.0    -> 10 points (likely generated)
        no vowels       -> 10 points (definitely not a word)
    """
    max_score = 10
    VOWELS = set("aeiou")
    COMMON_SUBDOMAINS = {"www", "ftp", "smtp", "ns", "ns1", "ns2", "mx", "vpn", "cdn", "ssh"}
    def run(self, domain, subdomain):
        """Run consonant/vowel analysis on the subdomain.
        Args:
            domain: Full domain string
            subdomain: Subdomain portion (not used for this check)
        Returns:
            dict with name, score, flagged, detail, and ratio value
        """
        if subdomain.lower() in self.COMMON_SUBDOMAINS:
            return {
                "name": "Consonant/Vowel Ratio",
                "score": 0,
                "flagged": False,
                "detail": f"Common subdomain '{subdomain}' - skipped",
                "ratio": None,
            }
        alpha_chars = [c for c in subdomain.lower() if c.isalpha()]
        if not alpha_chars:
            return {
                "name": "Consonant/Vowel Ratio",
                "score": 8,
                "flagged": True,
                "detail": "No alphabetic characters in subdomain - likely encoded data",
                "ratio": None,
            }
        vowels = sum(1 for c in alpha_chars if c in self.VOWELS)
        consonants = len(alpha_chars) - vowels
        if vowels == 0:
            ratio = None
            score = 10
            detail = "No vowels found - not a natural word"
        else:
            ratio = round(consonants / vowels, 2)
            if ratio > 6.0:
                score = 10
                detail = f"Very high consonant/vowel ratio ({ratio}) - likely generated"
            elif ratio > 4.0:
                score = 5
                detail = f"High consonant/vowel ratio ({ratio}) - unusual"
            else:
                score = 0
                detail = f"Normal consonant/vowel ratio ({ratio})"
        return {
            "name": "Consonant/Vowel Ratio",
            "score": score,
            "flagged": score >= 5,
            "detail": detail,
            "ratio": ratio,
        }