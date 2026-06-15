"""Validation utilities for domains and wordlists."""

import re
import os
from typing import List


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def validate_wordlist(wordlist_file: str) -> str:
    """Validate and create default wordlist if needed."""
    if not os.path.exists(wordlist_file):
        default_words = [
            "www",
            "mail",
            "ftp",
            "admin",
            "blog",
            "dev",
            "test",
            "api",
            "cdn",
            "vpn",
            "ns1",
            "ns2",
            "smtp",
            "pop3",
            "imap",
            "webmail",
            "cpanel",
            "whm",
            "mysql",
            "database",
            "backup",
            "storage",
            "cloud",
            "app",
            "apps",
            "portal",
            "dashboard",
            "status",
            "stats",
            "monitor",
            "monitoring",
            "logs",
            "log",
            "metrics",
            "trace",
            "jenkins",
            "gitlab",
            "github",
            "bitbucket",
            "jira",
            "confluence",
            "wiki",
            "docs",
            "documentation",
            "support",
            "help",
            "forum",
            "community",
            "news",
            "shop",
            "store",
            "cart",
            "checkout",
            "payment",
            "gateway",
            "billing",
        ]
        with open(wordlist_file, "w") as f:
            f.write("\n".join(default_words))

    return wordlist_file


def sanitize_subdomain(subdomain: str) -> str:
    """Sanitize subdomain string."""
    return subdomain.strip().lower().rstrip(".")