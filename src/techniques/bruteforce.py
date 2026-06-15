"""Bruteforce technique using wordlist."""

from typing import Callable, List, Optional, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController


class BruteforceSubdomains(BaseTechnique):
    """Bruteforce using external wordlist."""

    def __init__(
        self,
        domain: str,
        wordlist: List[str],
        logger: SubdomainLogger,
        controller: InteractiveController,
        threads: int = 50,
        timeout: int = 5,
    ):
        super().__init__(domain, logger, controller, "bruteforce")
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.current_index = 0

    def run(self, dns_lookup_callback: Callable = None, **kwargs) -> Set[str]:
        """Run bruteforce technique."""
        total = len(self.wordlist)
        start_index = self.current_index

        found_count = 0

        self.controller.stop_technique = False
        self.controller.skip_current = False

        batch_size = 100
        for batch_start in range(start_index, total, batch_size):
            self.controller.wait_if_paused()

            if self.controller.stop_technique:
                print(f"\n{Fore.YELLOW}[!] Stopping bruteforce by user request{Fore.RESET}")
                self.current_index = batch_start
                break

            if self.controller.should_skip():
                self.controller.reset_skip()
                print(f"\n{Fore.YELLOW}[!] Skipping bruteforce by user request{Fore.RESET}")
                self.current_index = batch_start
                break

            batch_end = min(batch_start + batch_size, total)
            batch_words = self.wordlist[batch_start:batch_end]

            if dns_lookup_callback:
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {}
                    for word in batch_words:
                        if self.controller.stop_technique:
                            break
                        futures[executor.submit(dns_lookup_callback, word, self.technique_name)] = word

                    for future in as_completed(futures):
                        self.controller.wait_if_paused()
                        if self.controller.stop_technique:
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                        try:
                            if future.result():
                                found_count += 1
                        except Exception:
                            pass

            self.current_index = batch_end
            self._print_progress(batch_end, total)

        print(f"\n{Fore.GREEN}[+] Bruteforce completed! Found {found_count} new subdomains{Fore.RESET}")
        self.logger.log_raw(f"Found {found_count} subdomains from {self.technique_name}", "INFO")

        return set()