"""DNS utilities for lookups and resolution."""

import time
import threading
from typing import List, Optional

import dns.resolver


class DNSUtils:
    """DNS utilities with rate limiting and resolver pooling."""

    def __init__(self, threads: int = 50, timeout: int = 5):
        self.threads = threads
        self.timeout = timeout
        self.request_times = []
        self.rate_limit_lock = threading.Lock()

        self.resolver_pool = []
        for _ in range(threads):
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            self.resolver_pool.append(resolver)
        self.resolver_index = 0
        self.resolver_lock = threading.Lock()

    def get_resolver(self):
        """Get a resolver from the pool (thread-safe)."""
        with self.resolver_lock:
            resolver = self.resolver_pool[self.resolver_index]
            self.resolver_index = (self.resolver_index + 1) % len(self.resolver_pool)
            return resolver

    def rate_limit(self):
        """Apply rate limiting to avoid overwhelming DNS servers."""
        with self.rate_limit_lock:
            now = time.time()
            self.request_times = [t for t in self.request_times if now - t < 1]
            if len(self.request_times) >= self.threads:
                time.sleep(0.05)
            self.request_times.append(now)

    def lookup(self, full_domain: str, retry_count: int = 2) -> Optional[List[str]]:
        """Perform DNS lookup with rate limiting and retry logic."""
        self.rate_limit()

        for attempt in range(retry_count):
            try:
                resolver = self.get_resolver()
                answers = resolver.resolve(full_domain, "A")
                return [str(answer) for answer in answers]
            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.Timeout:
                if attempt == retry_count - 1:
                    return None
                time.sleep(0.1)
            except Exception:
                return None

        return None