"""Certificate Transparency logs technique using crt.sh."""

import asyncio
import random
from typing import Callable, Optional, Set

from atomhttp import AtomHTTP
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController
from utils.http import USER_AGENTS


class CertificateTransparency(BaseTechnique):
    """Get subdomains from Certificate Transparency logs."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        use_random_agent: bool = False,
        timeout: int = 5,
    ):
        super().__init__(domain, logger, controller, "crt.sh")
        self.use_random_agent = use_random_agent
        self.timeout = timeout

    async def fetch_certificates(self) -> Set[str]:
        """Fetch certificate data from crt.sh."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()

        try:
            headers = {}
            if self.use_random_agent:
                headers["User-Agent"] = random.choice(USER_AGENTS)

            client = AtomHTTP({"timeout": self.timeout, "headers": headers})
            response = await client.get(url)

            if response.status == 200:
                data = response.data
                for entry in data[:500]:
                    self.controller.wait_if_paused()
                    if self.controller.stop_technique:
                        break

                    name = entry.get("name_value", "")
                    if name:
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
                                subdomains.add(subdomain)

            await client.close()

        except Exception as e:
            print(f"{Fore.RED}[-] crt.sh error: {str(e)[:50]}{Fore.RESET}")
            self.logger.log_raw(f"crt.sh error: {str(e)}", "ERROR")

        return subdomains

    def run(self, dns_lookup_callback: Callable = None, **kwargs) -> Set[str]:
        """Run certificate transparency technique."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            subdomains = loop.run_until_complete(self.fetch_certificates())
        finally:
            loop.close()

        found = 0
        for subdomain in subdomains:
            self.controller.wait_if_paused()
            if self.controller.stop_technique:
                break

            sub_part = subdomain.replace(f".{self.domain}", "")
            if dns_lookup_callback and dns_lookup_callback(sub_part, self.technique_name):
                found += 1

        print(f"\n{Fore.GREEN}[+] Found {found} new subdomains from {self.technique_name}{Fore.RESET}")
        self.logger.log_raw(f"Found {found} subdomains from {self.technique_name}", "INFO")

        return subdomains