#!/usr/bin/env python3

"""Redis caching layer for external API results."""

import json
import redis


class RedisCache:
    """Simple Redis cache for WHOIS and VirusTotal results."""

    def __init__(self, host="localhost", port=6379, ttl=3600):
        self.ttl = ttl
        self.client = redis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self.client.ping()

    def get(self, key):
        value = self.client.get(key)
        if value:
            return json.loads(value)
        return None

    def set(self, key, value, ttl=None):
        self.client.setex(
            key,
            ttl or self.ttl,
            json.dumps(value, default=str)
        )