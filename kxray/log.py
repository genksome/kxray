GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
RESET = "\033[0m"

def info(msg):
    print(f"{YELLOW}[*]{RESET} {msg}")

def ok(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def warn(msg):
    print(f"{RED}[-]{RESET} {msg}")

def err(msg):
    print(f"{RED}[!]{RESET} {msg}")

def debug(msg):
    print(f"{MAGENTA}[D]{RESET} {msg}")

def hint(msg):
    print(f"{CYAN}[?]{RESET} {msg}")

def title(msg):
    print(f"{BLUE}{msg}{RESET}")
