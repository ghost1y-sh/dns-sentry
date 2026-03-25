#!/usr/bin/env python3
"""VirusTotal API reputation check for known malicious domains."""
import time
import threading
import requests
class VirusTotalCheck:
    """Check domain reputation via VirusTotal API v3.
    VirusTotal aggregates results from 70+ security vendors.
    A domain flagged by multiple vendors is a strong signal.
    This check is optional - it degrades gracefully without
    an API key.
    Rate limited to 1 request per 15 seconds to stay within
    the free tier limit of 4 requests per minute.
    Scoring:
        0 detections    -> 0 points
        1-3 detections  -> 15 points
        4-9 detections  -> 30 points
        10+ detections  -> 40 points
        no API key      -> 0 points (skip gracefully)
    """
    max_score = 40
    VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
    _last_request_time = 0
    _rate_lock = threading.Lock()
    RATE_LIMIT_SECONDS = 15
    def __init__(self, api_key=None, cache=None):
        self.api_key = api_key
        self.cache = cache
    def _rate_limit_wait(self):
        """Wait if needed to respect VT rate limits."""
        with self._rate_lock:
            now = time.time()
            elapsed = now - VirusTotalCheck._last_request_time
            if elapsed < self.RATE_LIMIT_SECONDS:
                time.sleep(self.RATE_LIMIT_SECONDS - elapsed)
            VirusTotalCheck._last_request_time = time.time()
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
        # Rate limit before making the API call
        self._rate_limit_wait()
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
                    score = 40
                    detail = f"{detections} vendors flagged this domain - known malicious"
                elif detections >= 4:
                    score = 30
                    detail = f"{detections} vendors flagged this domain - suspicious"
                elif detections >= 1:
                    score = 15
                    detail = f"{detections} vendor(s) flagged this domain"
                else:
                    score = 0
                    detail = "Clean - no vendors flagged this domain"
                result = {
                    "name": "VirusTotal Reputation",
                    "score": score,
                    "flagged": score >= 15,
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