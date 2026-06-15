"""Wayback Machine technique for historical subdomains."""

import re
import asyncio
import random
from typing import Callable, Optional, Set

from atomhttp import AtomHTTP
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController
from utils.http import USER_AGENTS


class WaybackMachine(BaseTechnique):
    """Get historical subdomains from Wayback Machine."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        use_random_agent: bool = False,
    ):
        super().__init__(domain, logger, controller, "wayback")
        self.use_random_agent = use_random_agent

    async def fetch_wayback_data(self) -> Set[str]:
        """Fetch historical data from Wayback Machine."""
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
        subdomains = set()

        try:
            headers = {}
            if self.use_random_agent:
                headers["User-Agent"] = random.choice(USER_AGENTS)

            client = AtomHTTP({"timeout": 10, "headers": headers})
            response = await client.get(url)

            if response.status == 200:
                data = response.data

                for entry in data[1:1000]:
                    self.controller.wait_if_paused()
                    if self.controller.stop_technique:
                        break

                    if len(entry) > 2:
                        url_str = entry[2]
                        match = re.search(r"([a-zA-Z0-9\-\.]+\.?" + re.escape(self.domain) + ")", url_str)
                        if match:
                            subdomain = match.group(1)
                            subdomains.add(subdomain)

            await client.close()

        except Exception as e:
            print(f"{Fore.RED}[-] wayback error: {str(e)[:50]}{Fore.RESET}")
            self.logger.log_raw(f"wayback error: {str(e)}", "ERROR")

        return subdomains

    def run(self, dns_lookup_callback: Callable = None, **kwargs) -> Set[str]:
        """Run Wayback Machine technique."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            subdomains = loop.run_until_complete(self.fetch_wayback_data())
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