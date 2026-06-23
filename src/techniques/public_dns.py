"""Public DNS datasets technique using BufferOver and similar services."""

import asyncio
import random
from typing import Callable, Optional, Set

from atomhttp import AtomHTTP
from colorama import Fore

from .base import BaseTechnique
from ..core.logger import SubdomainLogger
from ..core.controller import InteractiveController
from ..utils.http import USER_AGENTS


class PublicDNSDatasets(BaseTechnique):
    """Query public DNS datasets."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        use_random_agent: bool = False,
        timeout: int = 10,
    ):
        super().__init__(domain, logger, controller, "bufferover")
        self.use_random_agent = use_random_agent
        self.timeout = timeout

    async def fetch_bufferover_data(self) -> Set[str]:
        """Fetch DNS data from BufferOver."""
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        subdomains = set()

        try:
            headers = {}
            if self.use_random_agent:
                headers["User-Agent"] = random.choice(USER_AGENTS)

            client = AtomHTTP({"timeout": self.timeout, "headers": headers})
            response = await client.get(url)

            if response.status == 200:
                data = response.data
                results = data.get("FDNS_A", [])

                for result in results[:500]:
                    self.controller.wait_if_paused()
                    if self.controller.stop_technique:
                        break

                    if isinstance(result, list) and len(result) > 1:
                        hostname = result[1]
                        if hostname.endswith(self.domain):
                            subdomains.add(hostname)

            await client.close()

        except Exception as e:
            print(f"{Fore.RED}[-] bufferover error: {str(e)[:50]}{Fore.RESET}")
            self.logger.log_raw(f"bufferover error: {str(e)}", "ERROR")

        return subdomains

    def run(self, dns_lookup_callback: Callable = None, **kwargs) -> Set[str]:
        """Run public DNS datasets technique."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            subdomains = loop.run_until_complete(self.fetch_bufferover_data())
        finally:
            loop.close()

        found = 0
        for subdomain in subdomains:
            self.controller.wait_if_paused()
            if self.controller.stop_technique:
                break

            if dns_lookup_callback and dns_lookup_callback(subdomain, self.technique_name):
                found += 1

        print(f"\n{Fore.GREEN}[+] Found {found} new subdomains from {self.technique_name}{Fore.RESET}")
        self.logger.log_raw(f"Found {found} subdomains from {self.technique_name}", "INFO")

        return subdomains