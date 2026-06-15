"""Interactive controller for handling user input and pause/resume functionality."""

import sys
import time
import threading
import signal
from colorama import Fore


class InteractiveController:
    """Handle user interactions and keyboard interrupts."""

    def __init__(self, scanner=None):
        self.should_continue = True
        self.skip_current = False
        self.stop_technique = False
        self.is_paused = False
        self.verbosity = 2
        self.interrupt_count = 0
        self.last_interrupt_time = 0
        self.pause_event = threading.Event()
        self.pause_event.set()  # Initially not paused
        self.in_menu = False  # Track if we're in menu to prevent re-entry
        self.scanner = scanner  # Reference to scanner for saving state
        signal.signal(signal.SIGINT, self.signal_handler)

    def set_scanner(self, scanner):
        """Set scanner reference for state saving."""
        self.scanner = scanner

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C - PAUSE the current operation."""
        # Prevent re-entering the menu if already in menu
        if self.in_menu:
            print(f"\n{Fore.RED}[!] Already in menu. Press Q to quit or wait...{Fore.RESET}")
            return

        current_time = time.time()

        if current_time - self.last_interrupt_time > 5:
            self.interrupt_count = 0

        self.interrupt_count += 1
        self.last_interrupt_time = current_time

        if self.interrupt_count >= 3:
            print(f"\n\n{Fore.RED}[!] Three consecutive interrupts detected! Saving state and exiting...{Fore.RESET}")
            # Save state before exiting
            if self.scanner:
                print(f"{Fore.YELLOW}[*] Saving current state...{Fore.RESET}")
                self.scanner.save_current_state("interrupted")
                print(f"{Fore.GREEN}[+] State saved to logs/{self.scanner.domain}/state.pkl{Fore.RESET}")
            print(f"{Fore.RED}[!] Exiting...{Fore.RESET}")
            sys.exit(0)

        # PAUSE the current operation
        self.is_paused = True
        self.pause_event.clear()
        print(f"\n\n{Fore.YELLOW}[!] Operation PAUSED (Ctrl+C {3 - self.interrupt_count} more times to force exit and save){Fore.RESET}")
        self.show_interactive_menu()

    def wait_if_paused(self):
        """Wait if the operation is paused."""
        self.pause_event.wait()

    def resume(self):
        """Resume the paused operation."""
        self.is_paused = False
        self.pause_event.set()

    def show_interactive_menu(self):
        """Show interactive menu on interrupt."""
        self.in_menu = True
        print(f"\n{Fore.CYAN}How do you want to proceed? [(S)kip current test/(E)nd detection phase/(N)ext technique/(C)hange verbosity/(R)esume/(Q)uit]{Fore.RESET}")

        while True:
            try:
                # Use sys.stdin.readline instead of input to avoid readline issues
                sys.stdout.write(f"{Fore.WHITE}Your choice: {Fore.RESET}")
                sys.stdout.flush()
                choice = sys.stdin.readline().strip().upper()

                if not choice:
                    continue

                if choice in ["S", "SKIP"]:
                    self.skip_current = True
                    self.resume()
                    print(f"{Fore.GREEN}[+] Skipping current operation...{Fore.RESET}")
                    break
                elif choice in ["E", "END"]:
                    self.stop_technique = True
                    self.should_continue = False
                    self.resume()
                    print(f"{Fore.YELLOW}[!] Stopping current detection phase...{Fore.RESET}")
                    break
                elif choice in ["N", "NEXT"]:
                    self.stop_technique = True
                    self.should_continue = False
                    self.resume()
                    print(f"{Fore.BLUE}[+] Moving to next technique...{Fore.RESET}")
                    break
                elif choice in ["C", "CHANGE"]:
                    self.change_verbosity()
                    # Don't resume, stay in menu
                    print(f"{Fore.CYAN}[*] Verbosity changed. Press R to resume{Fore.RESET}")
                elif choice in ["R", "RESUME"]:
                    self.resume()
                    print(f"{Fore.GREEN}[+] Resuming operation...{Fore.RESET}")
                    break
                elif choice in ["Q", "QUIT"]:
                    print(f"{Fore.YELLOW}[*] Saving state before quitting...{Fore.RESET}")
                    if self.scanner:
                        self.scanner.save_current_state("interrupted")
                        print(f"{Fore.GREEN}[+] State saved to logs/{self.scanner.domain}/state.pkl{Fore.RESET}")
                    print(f"{Fore.RED}[!] Quitting...{Fore.RESET}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}[-] Invalid choice. Enter S, E, N, C, R, or Q{Fore.RESET}")
            except (EOFError, KeyboardInterrupt):
                print(f"{Fore.YELLOW}[!] Returning to scan...{Fore.RESET}")
                self.resume()
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")
                self.resume()
                break

        self.in_menu = False

    def change_verbosity(self):
        """Change output verbosity level."""
        print(f"\n{Fore.CYAN}Current verbosity level: {self.verbosity}{Fore.RESET}")
        print(f"  0 - {Fore.RED}Quiet (only results){Fore.RESET}")
        print(f"  1 - {Fore.YELLOW}Normal (basic info){Fore.RESET}")
        print(f"  2 - {Fore.GREEN}Verbose (detailed output){Fore.RESET}")

        try:
            sys.stdout.write(f"{Fore.WHITE}Enter new verbosity level (0-2): {Fore.RESET}")
            sys.stdout.flush()
            new_level = int(sys.stdin.readline().strip())
            if 0 <= new_level <= 2:
                self.verbosity = new_level
                print(f"{Fore.GREEN}[+] Verbosity changed to {new_level}{Fore.RESET}")
            else:
                print(f"{Fore.RED}[-] Invalid level{Fore.RESET}")
        except Exception:
            print(f"{Fore.RED}[-] Invalid input{Fore.RESET}")

    def reset_skip(self):
        """Reset skip flag after it's been used."""
        self.skip_current = False

    def should_skip(self) -> bool:
        """Check if current operation should be skipped."""
        return self.skip_current