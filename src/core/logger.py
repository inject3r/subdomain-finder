"""Professional logging system with folder structure."""

import json
import pickle
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..models.state import ScanState


class SubdomainLogger:
    """Professional logging system with folder structure."""

    def __init__(self, domain: str):
        self.domain = domain
        self.base_dir = Path("logs") / domain
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.result_file = self.base_dir / "result.txt"
        self.state_file = self.base_dir / "state.pkl"
        self.details_file = self.base_dir / "details.json"
        self.raw_file = self.base_dir / "raw_output.log"
        self.crawl_file = self.base_dir / "crawled_urls.txt"
        self.dns_records_file = self.base_dir / "dns_records.txt"

        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.found_cache = set()

        self._init_log_files()

    def _init_log_files(self):
        """Initialize log files with headers."""
        with open(self.result_file, "w") as f:
            f.write(f"# Subdomain Discovery Results for {self.domain}\n")
            f.write(f"# Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {'='*60}\n\n")

        with open(self.raw_file, "w") as f:
            f.write(f"[{self.start_time.strftime('%H:%M:%S')}] Scan started for {self.domain}\n")

        with open(self.dns_records_file, "w") as f:
            f.write(f"# DNS Records for {self.domain}\n")
            f.write(f"# {'='*60}\n\n")

    def log_result(self, subdomain: str, ips: List[str], technique: str):
        """Log discovered subdomain (duplicate protected)."""
        cache_key = f"{subdomain}:{technique}"
        if cache_key in self.found_cache:
            return

        self.found_cache.add(cache_key)
        timestamp = datetime.now().strftime("%H:%M:%S")
        ip_str = ", ".join(ips) if ips else "No IP"

        with self.lock:
            with open(self.result_file, "a") as f:
                f.write(f"{subdomain:<50} -> {ip_str:<30} [{technique}]\n")
            with open(self.raw_file, "a") as f:
                f.write(f"[{timestamp}] [{technique.upper()}] Found: {subdomain} -> {ip_str}\n")

    def log_dns_record(self, record_type: str, name: str, value: str):
        """Log DNS record findings."""
        with self.lock:
            with open(self.dns_records_file, "a") as f:
                f.write(f"{record_type:<10} {name:<50} -> {value}\n")

    def log_raw(self, message: str, level: str = "INFO"):
        """Log raw message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            with open(self.raw_file, "a") as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")

    def log_crawled_url(self, url: str):
        """Log crawled URL."""
        with self.lock:
            with open(self.crawl_file, "a") as f:
                f.write(f"{url}\n")

    def save_state(self, state: ScanState):
        """Save scan state for resume."""
        with self.lock:
            with open(self.state_file, "wb") as f:
                pickle.dump(state, f)
        self.log_raw(f"State saved - Technique: {state.current_technique}")

    def load_state(self) -> Optional[ScanState]:
        """Load previously saved state."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "rb") as f:
                    state = pickle.load(f)
                self.log_raw(f"State loaded - Previous technique: {state.current_technique}")
                return state
            except Exception:
                pass
        return None

    def save_details(self, details: Dict):
        """Save detailed information as JSON."""
        with self.lock:
            with open(self.details_file, "w") as f:
                json.dump(details, f, indent=2, default=str)

    def finish_scan(self, total_found: int, duration: float):
        """Finalize logging."""
        end_time = datetime.now()
        with open(self.result_file, "a") as f:
            f.write(f"\n# Scan Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Duration: {duration:.2f} seconds\n")
            f.write(f"# Total Subdomains Found: {total_found}\n")