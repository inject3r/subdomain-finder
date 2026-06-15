"""Main scanner orchestrating all discovery techniques."""

import time
import threading
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
from colorama import Fore

from core.logger import SubdomainLogger
from core.controller import InteractiveController
from models.state import ScanState
from utils.dns import DNSUtils
from techniques.html_crawler import HTMLSubdomainExtractor
from techniques.dns_any import DNSAnyQuery
from techniques.cert_transparency import CertificateTransparency
from techniques.wayback import WaybackMachine
from techniques.public_dns import PublicDNSDatasets
from techniques.permutations import SmartPermutations
from techniques.numeric import NumericPatterns
from techniques.bruteforce import BruteforceSubdomains


class AdvancedSubdomainFinder:
    """Main orchestrator for subdomain discovery."""

    def __init__(
        self,
        domain: str,
        threads: int = 50,
        wordlist_file: str = "list.txt",
        timeout: int = 5,
        resume: bool = False,
        max_crawl_pages: int = 50,
        use_random_agent: bool = False,
    ):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.resume = resume
        self.max_crawl_pages = max_crawl_pages
        self.use_random_agent = use_random_agent
        self.controller = InteractiveController()
        self.logger = SubdomainLogger(domain)
        self.dns_utils = DNSUtils(threads, timeout)

        # Set scanner reference in controller for state saving
        self.controller.set_scanner(self)

        self.wordlist = self._load_wordlist(wordlist_file)

        self.found_subdomains: Set[str] = set()
        self.tested_subdomains: Set[str] = set()
        self.subdomain_details: Dict = {}
        self.techniques_completed: List[str] = []
        self.current_wordlist_index = 0
        self.crawled_urls: Set[str] = set()
        self.extracted_subdomains: Set[str] = set()

        if resume:
            self._load_previous_state()

    def _load_wordlist(self, wordlist_file: str) -> List[str]:
        """Load wordlist from external file."""
        import os

        if not os.path.exists(wordlist_file):
            print(f"{Fore.RED}[-] Wordlist file '{wordlist_file}' not found!{Fore.RESET}")
            print(f"{Fore.YELLOW}[*] Creating default wordlist file...{Fore.RESET}")

            default_words = [
                "www",
                "mail",
                "ftp",
                "localhost",
                "webmail",
                "smtp",
                "pop",
                "ns1",
                "ns2",
                "cpanel",
                "whm",
                "autodiscover",
                "m",
                "imap",
                "test",
                "ns",
                "blog",
                "pop3",
                "dev",
                "www2",
                "admin",
                "forum",
                "news",
                "vpn",
                "ns3",
                "api",
                "cdn",
                "stage",
                "staging",
                "prod",
                "production",
                "backup",
            ]

            with open(wordlist_file, "w") as f:
                for word in default_words:
                    f.write(f"{word}\n")

            print(f"{Fore.GREEN}[+] Created {wordlist_file} with {len(default_words)} entries{Fore.RESET}")
            return default_words

        with open(wordlist_file, "r") as f:
            words = [line.strip() for line in f if line.strip()]

        print(f"{Fore.GREEN}[+] Loaded {len(words)} words from {wordlist_file}{Fore.RESET}")
        return words

    def _load_previous_state(self):
        """Load previous scan state."""
        state = self.logger.load_state()
        if state and state.domain == self.domain:
            print(f"{Fore.YELLOW}[!] Found previous scan state for {self.domain}{Fore.RESET}")
            print(f"    Last technique: {state.current_technique}")
            print(f"    Progress: {state.current_wordlist_index}/{len(state.wordlist)} words tested")
            print(f"    Found: {len(state.found_subdomains)} subdomains")

            choice = input(f"\n{Fore.CYAN}Resume from previous state? [Y/n]: {Fore.RESET}").upper()
            if choice != "N":
                self.found_subdomains = state.found_subdomains
                self.tested_subdomains = state.tested_subdomains
                self.current_wordlist_index = state.current_wordlist_index
                self.techniques_completed = state.techniques_completed
                self.subdomain_details = state.subdomain_details
                self.crawled_urls = state.crawled_urls if hasattr(state, "crawled_urls") else set()
                self.extracted_subdomains = state.extracted_subdomains if hasattr(state, "extracted_subdomains") else set()
                print(f"{Fore.GREEN}[+] Resuming from previous state{Fore.RESET}")
                return

        print(f"{Fore.GREEN}[+] Starting fresh scan{Fore.RESET}")

    def save_current_state(self, technique: str):
        """Save current scan state."""
        state = ScanState(
            domain=self.domain,
            current_technique=technique,
            tested_subdomains=self.tested_subdomains,
            found_subdomains=self.found_subdomains,
            current_wordlist_index=self.current_wordlist_index,
            wordlist=self.wordlist,
            start_time=time.time(),
            techniques_completed=self.techniques_completed,
            subdomain_details=self.subdomain_details,
            crawled_urls=self.crawled_urls,
            extracted_subdomains=self.extracted_subdomains,
        )
        self.logger.save_state(state)

    def dns_lookup(self, subdomain: str, technique: str, retry_count: int = 2) -> Optional[Tuple[str, List[str]]]:
        """Perform DNS lookup with rate limiting and retry logic."""
        full_domain = f"{subdomain}.{self.domain}" if not subdomain.endswith(self.domain) else subdomain

        if full_domain in self.tested_subdomains:
            return None

        result = self.dns_utils.lookup(full_domain, retry_count)

        if result and full_domain not in self.found_subdomains:
            self.found_subdomains.add(full_domain)
            self.subdomain_details[full_domain] = {
                "ips": result,
                "technique": technique,
                "timestamp": datetime.now().isoformat(),
            }

            if self.controller.verbosity >= 1:
                print(f"\n{Fore.GREEN}[+] [{technique.upper()}] {full_domain} -> {', '.join(result)}{Fore.RESET}")

            self.logger.log_result(full_domain, result, technique)
            self.tested_subdomains.add(full_domain)
            return (full_domain, result)

        self.tested_subdomains.add(full_domain)
        return None

    def html_crawler_extraction(self):
        """TECHNIQUE 1: Extract subdomains from HTML responses and links."""
        technique = "html-crawler"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        self.controller.stop_technique = False

        extractor = HTMLSubdomainExtractor(self.domain, self.logger, self.controller, self.use_random_agent)
        verified, extracted = extractor.run_sync_crawl(max_pages=self.max_crawl_pages)

        for sub in verified:
            if sub not in self.found_subdomains:
                self.found_subdomains.add(sub)
                self.tested_subdomains.add(sub)

        self.extracted_subdomains = extracted
        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def dns_any_query(self):
        """TECHNIQUE 2: DNS ANY Query to extract all DNS records."""
        technique = "dns-any"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        self.controller.stop_technique = False

        dns_any = DNSAnyQuery(self.domain, self.logger, self.controller, self.timeout)
        result = dns_any.run()
        
        if isinstance(result, tuple) and len(result) == 2:
            found_subs, records = result
        else:
            found_subs = set()
            records = {}
            print(f"{Fore.YELLOW}[!] Warning: DNS ANY query returned unexpected result{Fore.RESET}")

        for sub in found_subs:
            if sub not in self.found_subdomains:
                self.found_subdomains.add(sub)
                self.tested_subdomains.add(sub)
                if sub not in self.subdomain_details:
                    self.subdomain_details[sub] = {"technique": technique, "timestamp": datetime.now().isoformat()}

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def smart_permutations(self):
        """TECHNIQUE 6: Generate smart permutations of found subdomains."""
        technique = "permutations"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [{technique}] Generating smart permutations...{Fore.RESET}")

        if not self.found_subdomains:
            print(f"{Fore.YELLOW}[-] No subdomains found for permutations{Fore.RESET}")
            self.techniques_completed.append(technique)
            return

        perm = SmartPermutations(self.domain, self.logger, self.controller)
        perm.run(dns_lookup_callback=self.dns_lookup, found_subdomains=list(self.found_subdomains))

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def numeric_patterns(self):
        """TECHNIQUE 7: Check numeric subdomain patterns."""
        technique = "numeric"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [{technique}] Checking numeric patterns...{Fore.RESET}")

        numeric = NumericPatterns(self.domain, self.logger, self.controller)
        numeric.run(dns_lookup_callback=self.dns_lookup)

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def bruteforce_subdomains(self):
        """TECHNIQUE 8: Bruteforce using external wordlist."""
        technique = "bruteforce"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [{technique.upper()}] Starting bruteforce from {len(self.wordlist)} words...{Fore.RESET}")

        bf = BruteforceSubdomains(self.domain, self.wordlist, self.logger, self.controller, self.threads, self.timeout)
        bf.run(dns_lookup_callback=self.dns_lookup)

        self.current_wordlist_index = bf.current_index
        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def certificate_transparency(self):
        """TECHNIQUE 3: Get subdomains from Certificate Transparency logs."""
        technique = "crt.sh"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [crt.sh] Checking Certificate Transparency logs...{Fore.RESET}")
        self.logger.log_raw(f"Starting {technique} enumeration", "INFO")

        ct = CertificateTransparency(self.domain, self.logger, self.controller, self.use_random_agent, self.timeout)
        ct.run(dns_lookup_callback=self.dns_lookup)

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def wayback_machine(self):
        """TECHNIQUE 4: Get historical subdomains from Wayback Machine."""
        technique = "wayback"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [wayback] Fetching historical data...{Fore.RESET}")
        self.logger.log_raw(f"Starting {technique} enumeration", "INFO")

        wb = WaybackMachine(self.domain, self.logger, self.controller, self.use_random_agent)
        wb.run(dns_lookup_callback=self.dns_lookup)

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def public_dns_datasets(self):
        """TECHNIQUE 5: Query public DNS datasets."""
        technique = "bufferover"

        if technique in self.techniques_completed:
            print(f"{Fore.YELLOW}[*] Skipping {technique} (already completed){Fore.RESET}")
            return

        if self.controller.stop_technique:
            return

        self.save_current_state(technique)
        print(f"\n{Fore.CYAN}[*] [bufferover] Querying BufferOver DNS dataset...{Fore.RESET}")
        self.logger.log_raw(f"Starting {technique} enumeration", "INFO")

        pdns = PublicDNSDatasets(self.domain, self.logger, self.controller, self.use_random_agent, self.timeout)
        pdns.run(dns_lookup_callback=self.dns_lookup)

        self.techniques_completed.append(technique)
        self.save_current_state(technique)

    def run_all(self):
        """Run all techniques in order."""
        from __main__ import BANNER

        print(BANNER)

        start_time = time.time()
        current_time = datetime.now()
        print(f"{Fore.CYAN}[*] Starting @ {current_time.strftime('%H:%M:%S')}/{current_time.strftime('%Y-%m-%d/')}{Fore.RESET}\n")

        self.controller.stop_technique = False
        self.controller.skip_current = False

        techniques = [
            ("HTML Crawler", self.html_crawler_extraction),
            ("DNS ANY Query", self.dns_any_query),
            ("Certificate Transparency", self.certificate_transparency),
            ("Wayback Machine", self.wayback_machine),
            ("Public DNS", self.public_dns_datasets),
            ("Smart Permutations", self.smart_permutations),
            ("Numeric Patterns", self.numeric_patterns),
            ("Bruteforce", self.bruteforce_subdomains),
        ]

        for tech_name, tech_func in techniques:
            if self.controller.stop_technique:
                print(f"\n{Fore.YELLOW}[!] Detection phase stopped by user{Fore.RESET}")
                break
            tech_func()

        duration = time.time() - start_time

        print(f"\n{Fore.CYAN}{'='*60}{Fore.RESET}")
        print(f"{Fore.GREEN}[✓] Scan completed in {duration:.2f} seconds{Fore.RESET}")
        print(f"{Fore.GREEN}[✓] Total unique subdomains found: {len(self.found_subdomains)}{Fore.RESET}")

        self.logger.save_details(self.subdomain_details)
        self.logger.finish_scan(len(self.found_subdomains), duration)

        print(f"{Fore.GREEN}[✓] Results saved to: logs/{self.domain}/result.txt{Fore.RESET}")
        print(f"{Fore.GREEN}[✓] DNS records saved to: logs/{self.domain}/dns_records.txt{Fore.RESET}")
        print(f"{Fore.GREEN}[✓] Detailed report saved to: logs/{self.domain}/details.json{Fore.RESET}")

        if self.found_subdomains:
            print(f"\n{Fore.CYAN}Discovered Subdomains ({len(self.found_subdomains)} total):{Fore.RESET}")
            for subdomain in sorted(self.found_subdomains)[:30]:
                details = self.subdomain_details.get(subdomain, {})
                ips = ", ".join(details.get("ips", ["No IP"]))
                tech = details.get("technique", "unknown")
                print(f"  {Fore.WHITE}• {subdomain:<45} -> {ips:<30} [{tech}]{Fore.RESET}")

            if len(self.found_subdomains) > 30:
                print(f"  {Fore.YELLOW}... and {len(self.found_subdomains) - 30} more{Fore.RESET}")
        else:
            print(f"\n{Fore.YELLOW}[!] No subdomains discovered{Fore.RESET}")