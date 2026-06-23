"""Techniques module containing all subdomain discovery methods."""

from .html_crawler import HTMLSubdomainExtractor
from .dns_any import DNSAnyQuery
from .cert_transparency import CertificateTransparency
from .wayback import WaybackMachine
from .public_dns import PublicDNSDatasets
from .permutations import SmartPermutations
from .numeric import NumericPatterns
from .bruteforce import BruteforceSubdomains

__all__ = [
    "HTMLSubdomainExtractor",
    "DNSAnyQuery",
    "CertificateTransparency",
    "WaybackMachine",
    "PublicDNSDatasets",
    "SmartPermutations",
    "NumericPatterns",
    "BruteforceSubdomains",
]