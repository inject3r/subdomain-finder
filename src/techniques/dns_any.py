"""DNS ANY Query technique for extracting all DNS records."""

import re
from typing import Dict, List, Set, Tuple

import dns.resolver
import dns.query
import dns.zone
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController


class DNSAnyQuery(BaseTechnique):
    """Perform DNS ANY query to extract all DNS records."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        timeout: int = 5,
    ):
        super().__init__(domain, logger, controller, "dns-any")
        self.timeout = timeout
        self.ns_servers = []

    def get_ns_servers(self) -> List[str]:
        """Get NS servers for the domain."""
        ns_servers = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(self.domain, "NS")
            ns_servers = [str(answer).rstrip(".") for answer in answers]
        except Exception as e:
            self.logger.log_raw(f"Could not get NS servers: {str(e)}", "WARNING")

        return ns_servers

    def query_any_record(self, target: str) -> Dict[str, List[str]]:
        """Query ANY record for a specific target."""
        records = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": [],
            "PTR": [],
            "SRV": [],
            "CAA": [],
            "DS": [],
            "DNSKEY": [],
        }

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(target, "ANY")

            for answer in answers:
                rdtype = dns.rdatatype.to_text(answer.rdtype)
                value = str(answer)

                if rdtype in records:
                    records[rdtype].append(value)
                    self.logger.log_dns_record(rdtype, target, value)

        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            if self.controller.verbosity >= 2:
                print(f"{Fore.YELLOW}[-] ANY query failed for {target}: {str(e)[:50]}{Fore.RESET}")

        # Also try individual queries for common types if ANY didn't work
        if not any(records.values()):
            for qtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = self.timeout
                    answers = resolver.resolve(target, qtype)
                    for answer in answers:
                        records[qtype].append(str(answer))
                        self.logger.log_dns_record(qtype, target, str(answer))
                except Exception:
                    pass

        return records

    def extract_subdomains_from_records(self, records: Dict[str, List[str]]) -> Set[str]:
        """Extract subdomains from DNS records."""
        subdomains = set()

        for rtype, values in records.items():
            for value in values:
                # Pattern to find domain names
                pattern = r"([a-zA-Z0-9][a-zA-Z0-9\-\.]*\." + re.escape(self.domain) + r")"
                matches = re.findall(pattern, value, re.IGNORECASE)

                for match in matches:
                    match = match.strip().lower()
                    if match.endswith(self.domain) and match != self.domain:
                        subdomains.add(match)

                # Also extract from CNAME and MX records specifically
                if rtype in ["CNAME", "MX", "NS", "SRV"]:
                    parts = value.split()
                    for part in parts:
                        if self.domain in part:
                            domain_match = re.search(r"([a-zA-Z0-9\-\.]+\.?" + re.escape(self.domain) + r")", part)
                            if domain_match:
                                sub = domain_match.group(1).lower()
                                if sub != self.domain:
                                    subdomains.add(sub)

        return subdomains

    def run(self, dns_lookup_callback=None, **kwargs) -> Tuple[Set[str], Dict]:
        """Main DNS ANY query execution."""
        print(f"{Fore.CYAN}\n[*] [DNS ANY Query] Starting DNS ANY record enumeration...{Fore.RESET}")
        print(f"{Fore.YELLOW}[*] This will query all DNS records to find subdomains{Fore.RESET}")
        self.logger.log_raw("DNS ANY query started", "INFO")

        found_subdomains = set()
        all_records = {}

        # First, query the main domain
        self.controller.wait_if_paused()
        if self.controller.should_skip():
            self.controller.reset_skip()
            print(f"{Fore.YELLOW}[!] Skipping DNS ANY query{Fore.RESET}")
            return found_subdomains, all_records  # Always return tuple

        print(f"{Fore.CYAN}[*] Querying ANY record for: {self.domain}{Fore.RESET}")
        records = self.query_any_record(self.domain)
        all_records[self.domain] = records

        # Extract subdomains from main domain records
        subdomains = self.extract_subdomains_from_records(records)
        found_subdomains.update(subdomains)

        if subdomains:
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from main domain records{Fore.RESET}")
            for sub in subdomains:
                print(f"    {Fore.WHITE}• {sub}{Fore.RESET}")

        # Query NS servers for zone transfer attempts
        ns_servers = self.get_ns_servers()
        if ns_servers:
            print(f"{Fore.CYAN}[*] Found NS servers: {', '.join(ns_servers)}{Fore.RESET}")

            # Try zone transfer from each NS server
            for ns in ns_servers:
                self.controller.wait_if_paused()
                if self.controller.should_skip():
                    break

                try:
                    print(f"{Fore.CYAN}[*] Attempting zone transfer from {ns}...{Fore.RESET}")
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))

                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != "@" and subdomain != self.domain:
                            full_sub = f"{subdomain}.{self.domain}" if subdomain else self.domain
                            if full_sub != self.domain:
                                found_subdomains.add(full_sub)
                                print(f"{Fore.GREEN}[+] [ZONE TRANSFER] Found: {full_sub}{Fore.RESET}")
                                self.logger.log_dns_record("ZONE", full_sub, "Zone transfer")

                    print(f"{Fore.GREEN}[+] Zone transfer successful from {ns}{Fore.RESET}")
                    break
                except Exception as e:
                    if self.controller.verbosity >= 1:
                        print(f"{Fore.YELLOW}[-] Zone transfer failed for {ns}: {str(e)[:50]}{Fore.RESET}")

        # Query subdomains we already know to get their records
        known_subs = list(found_subdomains)[:50]  # Limit to avoid too many queries
        for sub in known_subs:
            self.controller.wait_if_paused()
            if self.controller.should_skip():
                break

            print(f"{Fore.CYAN}[*] Querying ANY record for: {sub}{Fore.RESET}")
            records = self.query_any_record(sub)
            all_records[sub] = records

            new_subs = self.extract_subdomains_from_records(records)
            for new_sub in new_subs:
                if new_sub not in found_subdomains and new_sub != self.domain:
                    found_subdomains.add(new_sub)
                    print(f"{Fore.GREEN}[+] Found in {sub} records: {new_sub}{Fore.RESET}")

        print(f"\n{Fore.GREEN}[+] DNS ANY Query completed!{Fore.RESET}")
        print(f"    Total unique subdomains found: {len(found_subdomains)}")

        return found_subdomains, all_records