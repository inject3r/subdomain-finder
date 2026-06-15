"""HTML Crawler technique for extracting subdomains from web pages."""

import re
import asyncio
from urllib.parse import urlparse, urljoin
from collections import deque
from typing import Set, Tuple, Optional
import random

from bs4 import BeautifulSoup
from atomhttp import AtomHTTP
from colorama import Fore

from techniques.base import BaseTechnique
from core.logger import SubdomainLogger
from core.controller import InteractiveController
from utils.http import USER_AGENTS


class HTMLSubdomainExtractor(BaseTechnique):
    """Extract subdomains from HTML responses and links using atomhttp."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        use_random_agent: bool = False,
    ):
        super().__init__(domain, logger, controller, "html-crawler")
        self.use_random_agent = use_random_agent
        self.visited_urls = set()
        self.extracted_subdomains = set()
        self.found_cache = set()
        self.client = None
        self.current_user_agent = None

    def get_client(self):
        """Get or create atomhttp client with current headers."""
        if self.use_random_agent:
            user_agent = random.choice(USER_AGENTS)
        else:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

        self.current_user_agent = user_agent

        if self.client is None:
            self.client = AtomHTTP({"timeout": 10, "headers": {"User-Agent": user_agent}, "maxRedirects": 5})
        else:
            self.client.defaults.headers["User-Agent"] = user_agent

        return self.client

    async def close_client(self):
        """Close the atomhttp client."""
        if self.client:
            await self.client.close()
            self.client = None

    def extract_subdomains_from_text(self, text: str) -> Set[str]:
        """Extract subdomains from text content using regex."""
        subdomains = set()

        pattern = r"([a-zA-Z0-9][a-zA-Z0-9\-]{1,62}\.){1,}" + re.escape(self.domain)

        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                full_match = "".join(match) + self.domain
            else:
                full_match = match + self.domain if not match.endswith(self.domain) else match

            full_match = full_match.strip().lower()
            if full_match.endswith(self.domain) and full_match != self.domain:
                subdomains.add(full_match)

        js_pattern = r'(?:var|let|const|window\.location|\.domain\s*=\s*["\'])([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r")"
        js_matches = re.findall(js_pattern, text, re.IGNORECASE)
        for match in js_matches:
            if match.endswith(self.domain) and match != self.domain:
                subdomains.add(match.lower())

        json_pattern = r'"(?:https?:\/\/)?([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')"'
        json_matches = re.findall(json_pattern, text, re.IGNORECASE)
        for match in json_matches:
            if match.endswith(self.domain) and match != self.domain:
                subdomains.add(match.lower())

        return subdomains

    def extract_links_from_html(self, html: str, base_url: str) -> Set[str]:
        """Extract all links from HTML content."""
        links = set()
        from bs4 import XMLParsedAsHTMLWarning
        import warnings

        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
            for attr in ["href", "src", "data-src", "action", "content"]:
                if tag.has_attr(attr):
                    url = tag[attr]
                    if url:
                        absolute_url = urljoin(base_url, url)
                        links.add(absolute_url)

        for meta in soup.find_all("meta"):
            if meta.get("http-equiv", "").lower() == "refresh" and meta.get("content"):
                content = meta.get("content")
                url_match = re.search(r"url=(.+)", content, re.IGNORECASE)
                if url_match:
                    absolute_url = urljoin(base_url, url_match.group(1))
                    links.add(absolute_url)

        return links

    async def fetch_url(self, url: str) -> Optional[tuple]:
        """Fetch a single URL using atomhttp."""
        client = self.get_client()
        try:
            response = await client.get(url, response_type="text")
            if response.status == 200:
                return url, response.data
        except Exception as e:
            if self.controller.verbosity >= 2:
                print(f"{Fore.YELLOW}[-] Error fetching {url}: {str(e)[:50]}{Fore.RESET}")
        return None

    async def crawl_and_extract(self, max_pages: int = 50, max_depth: int = 2) -> Tuple[Set[str], Set[str]]:
        """Main crawling and extraction function using atomhttp."""
        print(f"{Fore.CYAN}\n[*] [HTML Crawler] Starting HTML/Response analysis...{Fore.RESET}")
        if self.use_random_agent:
            print(f"{Fore.YELLOW}[*] Using random User-Agent for each request{Fore.RESET}")
        self.logger.log_raw("HTML crawler started", "INFO")

        start_urls = [f"https://{self.domain}", f"http://{self.domain}"]
        to_visit = deque([(url, 0) for url in start_urls])
        pages_visited = 0
        verified_subdomains = set()
        all_extracted = set()

        while to_visit and pages_visited < max_pages and not self.controller.stop_technique:
            self.controller.wait_if_paused()

            if self.controller.should_skip():
                self.controller.reset_skip()
                break

            url, depth = to_visit.popleft()

            if url in self.visited_urls:
                continue
            if depth > max_depth:
                continue

            self.visited_urls.add(url)

            if self.controller.verbosity >= 2:
                print(f"{Fore.BLUE}[*] Crawling: {url} (depth {depth}){Fore.RESET}")

            self.logger.log_crawled_url(url)

            if self.use_random_agent:
                self.get_client()

            result = await self.fetch_url(url)

            if result:
                fetched_url, html_content = result

                subdomains = self.extract_subdomains_from_text(html_content)
                for sub in subdomains:
                    if sub not in all_extracted and sub not in self.found_cache:
                        all_extracted.add(sub)
                        self.found_cache.add(sub)
                        if self.controller.verbosity >= 1:
                            print(f"{Fore.GREEN}[+] [HTML] Found: {sub}{Fore.RESET}")

                links = self.extract_links_from_html(html_content, url)
                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc.endswith(self.domain) or not parsed.netloc:
                        if link not in self.visited_urls:
                            to_visit.append((link, depth + 1))

                    if parsed.netloc and parsed.netloc.endswith(self.domain):
                        subdomain = parsed.netloc
                        if subdomain != self.domain and subdomain not in all_extracted and subdomain not in self.found_cache:
                            all_extracted.add(subdomain)
                            self.found_cache.add(subdomain)
                            if self.controller.verbosity >= 1:
                                print(f"{Fore.GREEN}[+] [LINK] Found: {subdomain}{Fore.RESET}")

                pages_visited += 1
                if pages_visited % 10 == 0:
                    print(
                        f"{Fore.CYAN}[*] Crawling progress: {pages_visited}/{max_pages} pages, "
                        f"Found {len(all_extracted)} unique subdomains{Fore.RESET}"
                    )

        print(f"\n{Fore.CYAN}[*] Verifying {len(all_extracted)} unique extracted subdomains with DNS...{Fore.RESET}")

        for subdomain in list(all_extracted):
            self.controller.wait_if_paused()
            if self.controller.stop_technique:
                break

            try:
                import dns.resolver

                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                answers = resolver.resolve(subdomain, "A")
                ips = [str(a) for a in answers]
                if ips:
                    verified_subdomains.add(subdomain)
                    print(f"{Fore.GREEN}[+] [VERIFIED] {subdomain} -> {', '.join(ips)}{Fore.RESET}")
                    self.logger.log_result(subdomain, ips, "html-crawler")
            except Exception:
                if self.controller.verbosity >= 2:
                    print(f"{Fore.YELLOW}[-] Unverified: {subdomain}{Fore.RESET}")

        print(f"\n{Fore.GREEN}[+] HTML Crawler completed!{Fore.RESET}")
        print(f"    Pages crawled: {pages_visited}")
        print(f"    Unique potential subdomains found: {len(all_extracted)}")
        print(f"    Verified subdomains: {len(verified_subdomains)}")

        await self.close_client()
        return verified_subdomains, all_extracted

    def run_sync_crawl(self, max_pages: int = 50, max_depth: int = 2) -> Tuple[Set[str], Set[str]]:
        """Synchronous wrapper for async crawl (runs event loop)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.crawl_and_extract(max_pages, max_depth))
        finally:
            loop.close()

    def run(self, dns_lookup_callback=None, **kwargs) -> Set[str]:
        """Run the HTML crawler technique."""
        verified, _ = self.run_sync_crawl()
        return verified