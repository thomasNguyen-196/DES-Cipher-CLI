"""User Interface components for the DES Cipher CLI."""

import os
import shutil
import sys
import threading
import time

# Optional enhancements (will be used only if installed)
try:
    import pyfiglet
except ImportError:
    pyfiglet = None

try:
    import colorama
    colorama.init()
except ImportError:
    colorama = None

try:
    import pyperclip
except ImportError:
    pyperclip = None

# ANSI colors (works on most modern terminals)
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
FG = {
    "red": CSI + "31m",
    "green": CSI + "32m",
    "yellow": CSI + "33m",
    "blue": CSI + "34m",
    "magenta": CSI + "35m",
    "cyan": CSI + "36m",
    "white": CSI + "37m",
}

# --- UI Utilities ---

def get_terminal_width() -> int:
    """Gets the current terminal width."""
    return shutil.get_terminal_size((80, 20)).columns


def clear():
    """Clears the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def center(text: str, width: int = None) -> str:
    """Centers text within the terminal width."""
    if width is None:
        width = get_terminal_width()
    return text.center(width)


def banner():
    """Prints the main application banner."""
    title = "DES CIPHER"
    subtitle = "CLI — Refactored Edition"
    width = get_terminal_width()
    if pyfiglet:
        fig = pyfiglet.figlet_format("DES", font="slant")
        print(FG["cyan"] + fig + RESET)
        print(center(FG["yellow"] + subtitle + RESET, width))
    else:
        print(FG["cyan"] + "=" * width + RESET)
        print(center(FG["cyan"] + title + RESET, width))
        print(center(FG["yellow"] + subtitle + RESET, width))
        print(FG["cyan"] + "=" * width + RESET)


def prompt(msg: str) -> str:
    """
    Displays a prompt to the user and returns their input.
    Handles Ctrl+C and exits gracefully.
    """
    try:
        return input(FG["green"] + msg + RESET)
    except (KeyboardInterrupt, EOFError):
        print("\n" + FG["magenta"] + "Thoát." + RESET)
        sys.exit(0)


def boxed(title: str, body: str):
    """
    Prints a body of text inside a styled box.

    Args:
        title: The title to display at the top of the box.
        body: The main content, which can contain newlines.
    """
    width = min(80, get_terminal_width() - 4)
    print(FG["blue"] + "┌" + "─" * width + "┐" + RESET)
    title_line = f" {title} "
    print(FG["blue"] + "│" + RESET + BOLD + center(title_line, width) + RESET + FG["blue"] + "│" + RESET)
    print(FG["blue"] + "├" + "─" * width + "┤" + RESET)
    for line in body.splitlines():
        # Naive line wrapping
        while line:
            print(FG["blue"] + "│" + RESET + line[:width].ljust(width) + FG["blue"] + "│" + RESET)
            line = line[width:]
    print(FG["blue"] + "└" + "─" * width + "┘" + RESET)


class Spinner:
    """A simple terminal spinner for long-running operations."""
    def __init__(self, msg: str = "Processing..."):
        self.msg = msg
        self.running = False
        self.thread = None
        self.chars = "|/-\\"

    def start(self):
        """Starts the spinner in a separate thread."""
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def _spin(self):
        i = 0
        while self.running:
            print(f"\r{FG['magenta']}{self.msg} {self.chars[i % len(self.chars)]}{RESET}", end="", flush=True)
            i += 1
            time.sleep(0.08)
        # Clear the spinner line
        print("\r" + " " * (len(self.msg) + 4) + "\r", end="", flush=True)

    def stop(self):
        """Stops the spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
