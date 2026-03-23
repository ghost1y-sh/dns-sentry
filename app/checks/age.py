#!/usr/bin/env python3

"""WHOIS domain age check for detecting newly registered domains."""

from datetime import datetime, timezone
import whois


class DomainAgeCheck:
    """Check domain registration age via WHOIS.

    Newly registered domains are a strong indicator of malicious
    intent. Attackers register domains immediately before campaigns
    to avoid reputation blocklists. Legitimate business domains are
    typically months or years old.

    Scoring:
        age > 365 days -> 0 points (established)
        age 90-365     -> 5 points (relatively new)
        age 30-90      -> 15 points (suspicious)
        age < 30       -> 25 points (very suspicious)
        lookup failed   -> 0 points (don't penalize on errors)
    """

    max_score = 25

    def __init__(self, cache=None):
        self.cache = cache

    def run(self, domain, subdomain):
        """Run WHOIS age check on the registered domain.

        Args:
            domain: Full domain string
            subdomain: Subdomain portion (not used for this check)

        Returns:
            dict with name, score, flagged, detail, and age_days value
        """
        #Extract the registered domain (last two parts)
        parts = domain.split(".")
        if len(parts) >= 2:
            registered_domain = ".".join(parts[-2:])
        else:
            registered_domain = domain

        #Check cache first
        cache_key = f"whois:{registered_domain}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            w = whois.whois(registered_domain)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                result = {
                    "name": "Domain Age",
                    "score": 0,
                    "flagged": False,
                    "detail": "WHOIS data available but no creation date found",
                    "age_days": None,
                }
            else:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                age_days = (now - creation_date).days

                if age_days < 30:
                    score = 25
                    detail = f"Domain registered {age_days} days ago - very new"
                elif age_days < 90:
                    score = 15
                    detail = f"Domain registered {age_days} days ago - relatively new"
                elif age_days < 365:
                    score = 5
                    detail = f"Domain registered {age_days} days ago"
                else:
                    score = 0
                    years = age_days // 365
                    detail = f"Domain registered ~{years} year(s) ago - established"

                result = {
                    "name": "Domain Age",
                    "score": score,
                    "flagged": score >= 15,
                    "detail": detail,
                    "age_days": age_days,
                }

        except Exception as e:
            result = {
                "name": "Domain Age",
                "score": 0,
                "flagged": False,
                "detail": f"WHOIS lookup failed: {str(e)[:80]}",
                "age_days": None,
            }

        #Cache the result
        if self.cache:
            self.cache.set(cache_key, result, ttl=86400)

        return result