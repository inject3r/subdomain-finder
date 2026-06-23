"""DNS ALL Records Query technique for extracting all DNS records."""

import re
from typing import Dict, List, Set, Tuple

import dns.resolver
import dns.query
import dns.zone
from colorama import Fore

from .base import BaseTechnique
from ..core.logger import SubdomainLogger
from ..core.controller import InteractiveController


class DNSAnyQuery(BaseTechnique):
    """Perform DNS ALL record queries to extract all DNS records."""

    # Complete list of DNS record types
    RECORD_TYPES = [
        'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 
        'SOA', 'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY',
        'RRSIG', 'NSEC', 'TLSA', 'NAPTR', 'LOC',
        'SPF', 'DKIM', 'DMARC', 'SSHFP', 'SVCB', 'HTTPS'
    ]

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        timeout: int = 5,
    ):
        super().__init__(domain, logger, controller, "dns-all-records")
        self.timeout = timeout
        self.ns_servers = []
        # Use reliable public DNS servers
        self.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

    def get_ns_servers(self) -> List[str]:
        """Get NS servers for the domain."""
        ns_servers = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.nameservers = self.nameservers
            answers = resolver.resolve(self.domain, "NS")
            ns_servers = [str(answer).rstrip(".") for answer in answers]
        except Exception as e:
            self.logger.log_raw(f"Could not get NS servers: {str(e)}", "WARNING")

        return ns_servers

    def query_all_records(self, target: str) -> Dict[str, List[str]]:
        """
        Query ALL DNS record types for a specific target.
        Replaces the deprecated ANY query with individual queries.
        """
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
            "RRSIG": [],
            "NSEC": [],
            "TLSA": [],
            "NAPTR": [],
            "LOC": [],
            "SPF": [],
            "DKIM": [],
            "DMARC": [],
            "SSHFP": [],
            "SVCB": [],
            "HTTPS": [],
        }

        # Query each record type individually
        for qtype in self.RECORD_TYPES:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.nameservers = self.nameservers
                
                answers = resolver.resolve(target, qtype)
                
                for answer in answers:
                    value = str(answer)
                    if qtype in records:
                        records[qtype].append(value)
                        self.logger.log_dns_record(qtype, target, value)
                        
            except dns.resolver.NoAnswer:
                # No records of this type, that's fine
                continue
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist
                if self.controller.verbosity >= 2:
                    print(f"{Fore.YELLOW}[-] Domain {target} does not exist{Fore.RESET}")
                break
            except dns.exception.Timeout:
                if self.controller.verbosity >= 2:
                    print(f"{Fore.YELLOW}[-] Timeout querying {qtype} for {target}{Fore.RESET}")
                continue
            except Exception as e:
                if self.controller.verbosity >= 2:
                    print(f"{Fore.YELLOW}[-] {qtype} query failed for {target}: {str(e)[:50]}{Fore.RESET}")
                continue

        # Special handling for DMARC and other common records
        self._query_common_records(target, records)
        
        return records

    def _query_common_records(self, target: str, records: Dict[str, List[str]]):
        """Query common subdomain records that might not be in standard DNS."""
        common_prefixes = ['_dmarc', '_domainkey', 'mail', 'smtp', 'pop', 'imap']
        
        for prefix in common_prefixes:
            if prefix in target:
                continue
            try:
                full_target = f"{prefix}.{target}"
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.nameservers = self.nameservers
                
                # Try TXT records for DMARC and DKIM
                if prefix in ['_dmarc', '_domainkey']:
                    answers = resolver.resolve(full_target, 'TXT')
                    for answer in answers:
                        value = str(answer)
                        records.setdefault('TXT', []).append(f"{full_target}: {value}")
                        self.logger.log_dns_record('TXT', full_target, value)
            except Exception:
                pass

    def extract_subdomains_from_records(self, records: Dict[str, List[str]]) -> Set[str]:
        """Extract subdomains from DNS records with improved pattern matching."""
        subdomains = set()
        
        # Patterns for different record types
        patterns = {
            'general': r"([a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.?" + re.escape(self.domain) + r")",
            'mx': r"(\d+\s+)?([a-zA-Z0-9\-\.]+\.?" + re.escape(self.domain) + r")",
            'srv': r"(\d+\s+\d+\s+\d+\s+)?([a-zA-Z0-9\-\.]+\.?" + re.escape(self.domain) + r")",
            'ns': r"([a-zA-Z0-9\-\.]+\.?" + re.escape(self.domain) + r")",
        }

        for rtype, values in records.items():
            for value in values:
                # Clean the value
                value = value.strip().rstrip('.')
                
                # Extract domains using appropriate pattern
                if rtype in ['MX', 'SRV']:
                    pattern = patterns['mx'] if rtype == 'MX' else patterns['srv']
                elif rtype in ['NS', 'CNAME']:
                    pattern = patterns['ns']
                else:
                    pattern = patterns['general']
                
                matches = re.findall(pattern, value, re.IGNORECASE)
                
                for match in matches:
                    # Handle tuple results from regex groups
                    if isinstance(match, tuple):
                        match = match[-1] if match[-1] else match[0]
                    
                    if not match:
                        continue
                        
                    # Clean the extracted domain
                    match = match.lower().strip().rstrip('.')
                    
                    # Validate it's a subdomain
                    if (self.domain in match and 
                        match != self.domain and 
                        len(match) > len(self.domain)):
                        subdomains.add(match)

                # Extra extraction for specific record types
                if rtype in ['MX', 'SRV', 'NS', 'CNAME']:
                    parts = value.split()
                    for part in parts:
                        part = part.strip().rstrip('.')
                        if self.domain in part and part != self.domain:
                            # Validate it's a proper domain name
                            if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\." + re.escape(self.domain) + r"$", part):
                                subdomains.add(part)

        return subdomains

    def run(self, dns_lookup_callback=None, **kwargs) -> Tuple[Set[str], Dict]:
        """Main DNS ALL records execution."""
        print(f"{Fore.CYAN}\n[*] [DNS ALL Records] Starting DNS record enumeration...{Fore.RESET}")
        print(f"{Fore.YELLOW}[*] This will query ALL DNS record types to find subdomains{Fore.RESET}")
        self.logger.log_raw("DNS ALL records query started", "INFO")

        found_subdomains = set()
        all_records = {}

        # First, query the main domain
        self.controller.wait_if_paused()
        if self.controller.should_skip():
            self.controller.reset_skip()
            print(f"{Fore.YELLOW}[!] Skipping DNS ALL records query{Fore.RESET}")
            return found_subdomains, all_records

        print(f"{Fore.CYAN}[*] Querying ALL records for: {self.domain}{Fore.RESET}")
        records = self.query_all_records(self.domain)
        all_records[self.domain] = records

        # Display found records
        found_types = [t for t, v in records.items() if v]
        if found_types:
            print(f"{Fore.GREEN}[+] Found {len(found_types)} record types: {', '.join(found_types)}{Fore.RESET}")
            for rtype, values in records.items():
                if values:
                    print(f"    {Fore.WHITE}• {rtype}: {len(values)} records{Fore.RESET}")
                    if self.controller.verbosity >= 1:
                        for val in values[:3]:  # Show first 3
                            print(f"        → {val}")
                        if len(values) > 3:
                            print(f"        ... and {len(values) - 3} more")

        # Extract subdomains from main domain records
        subdomains = self.extract_subdomains_from_records(records)
        found_subdomains.update(subdomains)

        if subdomains:
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from main domain records{Fore.RESET}")
            for sub in list(subdomains)[:10]:  # Show first 10
                print(f"    {Fore.WHITE}• {sub}{Fore.RESET}")
            if len(subdomains) > 10:
                print(f"    ... and {len(subdomains) - 10} more")

        # Query NS servers for zone transfer attempts
        ns_servers = self.get_ns_servers()
        if ns_servers:
            print(f"{Fore.CYAN}[*] Found NS servers: {', '.join(ns_servers)}{Fore.RESET}")

            # Try zone transfer from each NS server
            zone_transfer_success = False
            for ns in ns_servers:
                self.controller.wait_if_paused()
                if self.controller.should_skip():
                    break

                try:
                    print(f"{Fore.CYAN}[*] Attempting zone transfer from {ns}...{Fore.RESET}")
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))

                    zone_subdomains = set()
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != "@" and subdomain != self.domain:
                            full_sub = f"{subdomain}.{self.domain}" if subdomain else self.domain
                            if full_sub != self.domain:
                                zone_subdomains.add(full_sub)
                                print(f"{Fore.GREEN}[+] [ZONE TRANSFER] Found: {full_sub}{Fore.RESET}")
                                self.logger.log_dns_record("ZONE", full_sub, "Zone transfer")

                    found_subdomains.update(zone_subdomains)
                    print(f"{Fore.GREEN}[+] Zone transfer successful from {ns}! Found {len(zone_subdomains)} subdomains{Fore.RESET}")
                    zone_transfer_success = True
                    break
                    
                except dns.query.TransferError:
                    if self.controller.verbosity >= 1:
                        print(f"{Fore.YELLOW}[-] Zone transfer not allowed from {ns}{Fore.RESET}")
                except dns.exception.Timeout:
                    if self.controller.verbosity >= 1:
                        print(f"{Fore.YELLOW}[-] Zone transfer timeout from {ns}{Fore.RESET}")
                except Exception as e:
                    if self.controller.verbosity >= 1:
                        print(f"{Fore.YELLOW}[-] Zone transfer failed from {ns}: {str(e)[:50]}{Fore.RESET}")

            if not zone_transfer_success:
                print(f"{Fore.YELLOW}[!] Zone transfer not possible. Continuing with regular queries.{Fore.RESET}")

        # Query discovered subdomains for their records
        known_subs = list(found_subdomains)[:30]  # Limit to avoid rate limiting
        if known_subs:
            print(f"{Fore.CYAN}[*] Querying {len(known_subs)} discovered subdomains...{Fore.RESET}")
            
        for idx, sub in enumerate(known_subs, 1):
            self.controller.wait_if_paused()
            if self.controller.should_skip():
                break

            print(f"{Fore.CYAN}[*] [{idx}/{len(known_subs)}] Querying ALL records for: {sub}{Fore.RESET}")
            records = self.query_all_records(sub)
            all_records[sub] = records

            # Extract subdomains from this subdomain's records
            new_subs = self.extract_subdomains_from_records(records)
            for new_sub in new_subs:
                if new_sub not in found_subdomains and new_sub != self.domain:
                    found_subdomains.add(new_sub)
                    print(f"{Fore.GREEN}[+] Found in {sub} records: {new_sub}{Fore.RESET}")

        # Summary
        print(f"\n{Fore.GREEN}[+] DNS ALL Records query completed!{Fore.RESET}")
        print(f"    • Total unique subdomains found: {len(found_subdomains)}")
        print(f"    • Total domains queried: {len(all_records)}")
        
        # Statistics about record types found
        record_stats = {}
        for domain, records in all_records.items():
            for rtype, values in records.items():
                if values:
                    record_stats[rtype] = record_stats.get(rtype, 0) + len(values)
        
        if record_stats:
            print(f"    • Record type distribution:")
            for rtype, count in sorted(record_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"        - {rtype}: {count} records")

        return found_subdomains, all_records