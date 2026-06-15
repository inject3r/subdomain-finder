"""Base class for all discovery techniques."""

from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Set, Tuple, Any
from colorama import Fore

from core.logger import SubdomainLogger
from core.controller import InteractiveController


class BaseTechnique(ABC):
    """Abstract base class for all discovery techniques."""

    def __init__(
        self,
        domain: str,
        logger: SubdomainLogger,
        controller: InteractiveController,
        technique_name: str,
    ):
        self.domain = domain
        self.logger = logger
        self.controller = controller
        self.technique_name = technique_name

    @abstractmethod
    def run(self, *args, **kwargs) -> Any:
        """Run the discovery technique."""
        pass

    def run_sync(self, *args, **kwargs) -> Any:
        """Synchronous wrapper for the discovery technique."""
        return self.run(*args, **kwargs)

    def _print_progress(self, current: int, total: int, message: str = ""):
        """Print progress bar."""
        if self.controller.verbosity < 1:
            return

        percent = (current / total) * 100
        bar_length = 40
        filled = int(bar_length * current // total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)

        import sys
        sys.stdout.write(f'\r{self._get_color()}[{self.technique_name}] {bar} {percent:.1f}% ({current}/{total}) {message}{self._reset_color()}')
        sys.stdout.flush()

    def _get_color(self) -> str:
        """Get color for technique."""
        colors = {
            "html-crawler": Fore.CYAN,
            "dns-any": Fore.MAGENTA,
            "crt.sh": Fore.BLUE,
            "wayback": Fore.YELLOW,
            "bufferover": Fore.GREEN,
            "permutations": Fore.LIGHTBLUE_EX,
            "numeric": Fore.LIGHTCYAN_EX,
            "bruteforce": Fore.LIGHTRED_EX,
        }
        return colors.get(self.technique_name, Fore.WHITE)

    def _reset_color(self) -> str:
        """Reset color."""
        return Fore.RESET