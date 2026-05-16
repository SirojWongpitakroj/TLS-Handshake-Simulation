from colorama import init, Fore, Style
init(autoreset=True)

# --- Phase Colors ---
STARTUP  = Fore.CYAN    + Style.BRIGHT
PHASE1   = Fore.YELLOW  + Style.BRIGHT
PHASE2   = Fore.BLUE    + Style.BRIGHT
PHASE3   = Fore.MAGENTA + Style.BRIGHT
PHASE4   = Fore.WHITE   + Style.BRIGHT
PHASE5   = Fore.GREEN   + Style.BRIGHT
PHASE6   = Fore.RED     + Style.BRIGHT

# --- Status Colors ---
SUCCESS  = Fore.GREEN   + Style.BRIGHT
ERROR    = Fore.RED     + Style.BRIGHT
CIPHER   = Fore.YELLOW  + Style.BRIGHT


def banner(title):
    """Prints a full-width banner header."""
    print(STARTUP + "\n" + "="*50)
    print(STARTUP + f"  {title.center(48)}")
    print(STARTUP + "="*50 + "\n")


def phase_header(color, label):
    """Prints a phase section header."""
    print(color + f"\n--- {label} ---")


def log(color, msg):
    """Prints a standard indented phase log message."""
    print(color + f"  >> {msg}")


def session_complete():
    """Prints the final session complete banner."""
    print(STARTUP + "\n" + "="*50)
    print(STARTUP + "  " + "TLS SESSION COMPLETE".center(48))
    print(STARTUP + "="*50 + "\n")
