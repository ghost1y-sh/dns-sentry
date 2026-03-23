#!/usr/bin/env python3

"""VirusTotal API reputation check for known malicious domains."""

import requests


class VirusTotalCheck:
    """Check domain reputation via VirusTotal API v3.

    VirusTotal aggregates results from 70+ security vendors.
    A domain flagged by multiple vendors is a strong signal.
    This check is optional - it degrades gracefully without
    an API key.

    Scoring:
        0 detections    -> 0 points
        1-3 detections  -> 10 points
        4-9 detections  -> 20 points
        10+ detections  -> 30 points
        no API key      -> 0 points (skip gracefully)
    """

    max_score = 30

    VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

    def __init__(self, api_key=None, cache=None):
        self.api_key = api_key
        self.cache = cache

    def run(self, domain, subdomain):
        """Run VirusTotal reputation check.

        Args:
            domain: Full domain string
            subdomain: Subdomain portion (not used for this check)

        Returns:
            dict with name, score, flagged, detail, and detections count
        """
        if not self.api_key:
            return {
                "name": "VirusTotal Reputation",
                "score": 0,
                "flagged": False,
                "detail": "Skipped - no API key provided (set VT_API_KEY env var)",
                "detections": None,
            }

        parts = domain.split(".")
        if len(parts) >= 2:
            lookup_domain = ".".join(parts[-2:])
        else:
            lookup_domain = domain

        cache_key = f"vt:{lookup_domain}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                self.VT_URL.format(domain=lookup_domain),
                headers=headers,
                timeout=10,
            )

            if response.status_code == 404:
                result = {
                    "name": "VirusTotal Reputation",
                    "score": 0,
                    "flagged": False,
                    "detail": "Domain not found in VirusTotal database",
                    "detections": 0,
                }
            elif response.status_code != 200:
                result = {
                    "name": "VirusTotal Reputation",
                    "score": 0,
                    "flagged": False,
                    "detail": f"VirusTotal API returned status {response.status_code}",
                    "detections": None,
                }
            else:
                data = response.json()
                analysis = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}
                )
                malicious = analysis.get("malicious", 0)
                suspicious = analysis.get("suspicious", 0)
                detections = malicious + suspicious

                if detections >= 10:
                    score = 30
                    detail = f"{detections} vendors flagged this domain - known malicious"
                elif detections >= 4:
                    score = 20
                    detail = f"{detections} vendors flagged this domain - suspicious"
                elif detections >= 1:
                    score = 10
                    detail = f"{detections} vendor(s) flagged this domain"
                else:
                    score = 0
                    detail = "Clean - no vendors flagged this domain"

                result = {
                    "name": "VirusTotal Reputation",
                    "score": score,
                    "flagged": score >= 10,
                    "detail": detail,
                    "detections": detections,
                }

        except requests.exceptions.Timeout:
            result = {
                "name": "VirusTotal Reputation",
                "score": 0,
                "flagged": False,
                "detail": "VirusTotal API request timed out",
                "detections": None,
            }
        except Exception as e:
            result = {
                "name": "VirusTotal Reputation",
                "score": 0,
                "flagged": False,
                "detail": f"VirusTotal lookup failed: {str(e)[:80]}",
                "detections": None,
            }

        if self.cache:
            self.cache.set(cache_key, result, ttl=3600)

        return result