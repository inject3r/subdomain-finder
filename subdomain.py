#!/usr/bin/env python3
"""Main entry point for subdomain CLI tool."""

import sys
import argparse
from colorama import Fore, init
from src import __version__

from src import AdvancedSubdomainFinder
from src.utils.validators import validate_domain, validate_wordlist

init(autoreset=True)

BANNER = fr"""{Fore.CYAN}
      SUBDOMAIN FINDER
           SCAN       {Fore.RED}{{{__version__}}}{Fore.CYAN}
        /    |    \\
       /     |     \\
{Fore.GREEN}www.example{Fore.CYAN}  {Fore.YELLOW}mail{Fore.CYAN}  {Fore.MAGENTA}api{Fore.CYAN}
   /          |      \
{Fore.GREEN}dev.example{Fore.CYAN}  {Fore.YELLOW}smtp{Fore.CYAN}   {Fore.MAGENTA}v1.example{Fore.CYAN}
    |                 |
{Fore.GREEN}test.example{Fore.CYAN}      {Fore.MAGENTA}v2.example{Fore.CYAN}   {Fore.BLUE}https://github.com/inject3r/subdomain-finder{Fore.RESET}

{Fore.RED}[!] Legal disclaimer: Usage for attacking targets without prior mutual consent is illegal.
{Fore.YELLOW}    Users assume all liability and responsibility for any misuse or damage.{Fore.RESET}
"""

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description=f"Advanced Subdomain Discovery Tool v{__version__} - Professional Subdomain Enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  subdomain.py -d example.com
  subdomain.py -d example.com -t 100 --max-pages 100
  subdomain.py -d example.com --resume
  subdomain.py -d example.com --random-agent
  subdomain.py -d example.com -w custom_wordlist.txt --threads 200
        """,
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("-w", "--wordlist", default="list.txt", help="Wordlist file (default: list.txt)")
    parser.add_argument("--timeout", type=int, default=5, help="DNS timeout in seconds (default: 5)")
    parser.add_argument("--resume", action="store_true", help="Resume from previous scan")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent for HTTP requests")

    args = parser.parse_args()

    # Validate domain
    if not validate_domain(args.domain):
        print(f"{Fore.RED}[-] Invalid domain format: {args.domain}{Fore.RESET}")
        sys.exit(1)

    # Validate wordlist
    args.wordlist = validate_wordlist(args.wordlist)

    # Check dependencies
    try:
        import bs4  # noqa: F401
    except ImportError:
        print(f"{Fore.YELLOW}[!] BeautifulSoup4 not found. Installing...{Fore.RESET}")
        import os

        os.system("pip install beautifulsoup4 -q")
        print(f"{Fore.GREEN}[+] BeautifulSoup4 installed{Fore.RESET}")

    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        print(f"{Fore.YELLOW}[!] dnspython not found. Installing...{Fore.RESET}")
        import os

        os.system("pip install dnspython -q")
        print(f"{Fore.GREEN}[+] dnspython installed{Fore.RESET}")

    try:
        import atomhttp  # noqa: F401
    except ImportError:
        print(f"{Fore.YELLOW}[!] atomhttp not found. Installing...{Fore.RESET}")
        import os

        os.system("pip install atomhttp -q")
        print(f"{Fore.GREEN}[+] atomhttp installed{Fore.RESET}")

    # Run scanner
    scanner = AdvancedSubdomainFinder(
        domain=args.domain,
        threads=args.threads,
        wordlist_file=args.wordlist,
        timeout=args.timeout,
        resume=args.resume,
        max_crawl_pages=args.max_pages,
        use_random_agent=args.random_agent,
    )

    try:
        scanner.run_all()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Fore.RESET}")
        scanner.save_current_state("interrupted")
        print(f"{Fore.GREEN}[+] State saved. Use --resume to continue later{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {str(e)}{Fore.RESET}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()