"""Scan state model for resume functionality."""

from dataclasses import dataclass, field
from typing import Set, List, Dict


@dataclass
class ScanState:
    """Store scan state for resume functionality."""

    domain: str
    current_technique: str
    tested_subdomains: Set[str]
    found_subdomains: Set[str]
    current_wordlist_index: int
    wordlist: List[str]
    start_time: float
    techniques_completed: List[str]
    subdomain_details: Dict
    crawled_urls: Set[str] = field(default_factory=set)
    extracted_subdomains: Set[str] = field(default_factory=set)