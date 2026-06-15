"""Techniques module containing all subdomain discovery methods."""

from techniques.html_crawler import HTMLSubdomainExtractor
from techniques.dns_any import DNSAnyQuery
from techniques.cert_transparency import CertificateTransparency
from techniques.wayback import WaybackMachine
from techniques.public_dns import PublicDNSDatasets
from techniques.permutations import SmartPermutations
from techniques.numeric import NumericPatterns
from techniques.bruteforce import BruteforceSubdomains

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