"""Smart permutations technique for generating subdomain variations."""

from typing import Callable, List, Set, Optional, Any
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController


class SmartPermutations(BaseTechnique):
    """Generate smart permutations of found subdomains."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
    ):
        super().__init__(domain, logger, controller, "permutations")

    def generate_permutations(self, found_subdomains: List[str]) -> Set[str]:
        """Generate permutations from found subdomains."""
        patterns = [
            "dev-{sub}", "{sub}-test", "staging-{sub}", "old-{sub}",
            "api-{sub}", "admin-{sub}", "backup-{sub}", "new-{sub}",
            "app-{sub}", "portal-{sub}", "dashboard-{sub}", "manage-{sub}",
            "cdn-{sub}", "static-{sub}", "assets-{sub}", "media-{sub}",
            "{sub}-dev", "{sub}-staging", "{sub}-prod", "test-{sub}"
        ]

        permutations = set()
        for sub in found_subdomains[:30]:
            base = sub.replace(f".{self.domain}", "").split('.')[0]
            for pattern in patterns:
                perm = pattern.format(sub=base)
                if len(perm) < 30:
                    permutations.add(perm)

        return permutations

    def run(self, dns_lookup_callback: Callable = None, found_subdomains: List[str] = None, **kwargs) -> Set[str]:
        """Run smart permutations technique."""
        if not found_subdomains:
            print(f"{Fore.YELLOW}[-] No subdomains found for permutations{Fore.RESET}")
            return set()

        permutations = self.generate_permutations(found_subdomains)
        print(f"{Fore.CYAN}[*] Testing {len(permutations)} permutations{Fore.RESET}")

        found = 0
        total = len(permutations)
        for i, perm in enumerate(permutations):
            self.controller.wait_if_paused()

            if self.controller.should_skip():
                self.controller.reset_skip()
                print(f"\n{Fore.YELLOW}[!] Skipping permutation scan by user request{Fore.RESET}")
                break

            if self.controller.stop_technique:
                break

            if dns_lookup_callback:
                result = dns_lookup_callback(perm, self.technique_name)
                if result:
                    found += 1

            if total > 0 and i % 10 == 0:
                self._print_progress(i, total)

        print(f"\n{Fore.GREEN}[+] Found {found} new subdomains from {self.technique_name}{Fore.RESET}")
        self.logger.log_raw(f"Found {found} subdomains from {self.technique_name}", "INFO")

        return permutations