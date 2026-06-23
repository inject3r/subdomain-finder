"""Numeric patterns technique for checking numbered subdomains."""

from typing import Callable, Set, Optional, Any
from colorama import Fore

from .base import BaseTechnique
from ..core.logger import SubdomainLogger
from ..core.controller import InteractiveController


class NumericPatterns(BaseTechnique):
    """Check numeric subdomain patterns."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
    ):
        super().__init__(domain, logger, controller, "numeric")

    def generate_numeric_patterns(self) -> Set[str]:
        """Generate numeric subdomain patterns."""
        patterns = ["ns{}", "mail{}", "server{}", "web{}", "app{}", "db{}", "node{}", "host{}", "vps{}", "vm{}"]
        numeric_subs = set()

        for i in range(1, 21):
            for pattern in patterns:
                numeric_subs.add(pattern.format(i))

        for i in range(1, 11):
            for j in range(1, 6):
                numeric_subs.add(f"server{i}-{j}")
                numeric_subs.add(f"node{i}-{j}")

        return numeric_subs

    def run(self, dns_lookup_callback: Callable = None, **kwargs) -> Set[str]:
        """Run numeric patterns technique."""
        numeric_subs = self.generate_numeric_patterns()
        print(f"{Fore.CYAN}[*] Testing {len(numeric_subs)} numeric patterns{Fore.RESET}")

        found = 0
        total = len(numeric_subs)
        for i, sub in enumerate(numeric_subs):
            self.controller.wait_if_paused()

            if self.controller.should_skip():
                self.controller.reset_skip()
                print(f"\n{Fore.YELLOW}[!] Skipping numeric pattern scan by user request{Fore.RESET}")
                break

            if self.controller.stop_technique:
                break

            if dns_lookup_callback:
                result = dns_lookup_callback(sub, self.technique_name)
                if result:
                    found += 1

            if total > 0 and i % 10 == 0:
                self._print_progress(i, total)

        print(f"\n{Fore.GREEN}[+] Found {found} new subdomains from {self.technique_name}{Fore.RESET}")
        self.logger.log_raw(f"Found {found} subdomains from {self.technique_name}", "INFO")

        return numeric_subs