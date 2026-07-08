# aegis/display.py
import sys, time
from colorama import init, Fore, Style
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}██████╗  ██████╗ ███╗   ██╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗
{Fore.CYAN}██╔══██╗██╔═══██╗████╗  ██║    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
{Fore.CYAN}██████╔╝██║   ██║██╔██╗ ██║    ███████║███████║██║     █████╔╝ 
{Fore.CYAN}██╔══██╗██║   ██║██║╚██╗██║    ██╔══██║██╔══██║██║     ██╔═██╗ 
{Fore.CYAN}██║  ██║╚██████╔╝██║ ╚████║    ██║  ██║██║  ██║╚██████╗██║  ██╗
{Fore.CYAN}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Fore.GREEN}═══════════════════════════════════════════════════════════════════
{Fore.YELLOW}  🔥 ADVANCED EXPLOITATION & SECURITY TESTING SUITE 🔥
{Fore.CYAN}  ⚡ 6-Phase Lifecycle: Recon → Scan → Vuln → Exploit → Post → Report
{Fore.GREEN}═══════════════════════════════════════════════════════════════════
{Style.RESET_ALL}"""

def print_banner():
    for line in BANNER.split('\n'):
        print(line)
        time.sleep(0.005)

def status_success(msg): print(f"{Fore.GREEN}[✔] {msg}{Style.RESET_ALL}")
def status_error(msg): print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")
def status_warning(msg): print(f"{Fore.YELLOW}[⚠] {msg}{Style.RESET_ALL}")
def status_info(msg): print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
def status_shell(msg): print(f"{Fore.MAGENTA}[+] {msg}{Style.RESET_ALL}")
def colorize(text, color=Fore.WHITE): return f"{color}{text}{Style.RESET_ALL}"

def spinner(message="Loading", duration=2):
    chars = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f'\r{Fore.CYAN}{chars[i%len(chars)]} {message}{Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1); i += 1
    sys.stdout.write('\r' + ' ' * (len(message)+10) + '\r')

def progress_bar(current, total, prefix='Progress', length=30):
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    bar = '█' * filled + '─' * (length - filled)
    color = Fore.GREEN if percent < 0.7 else Fore.YELLOW if percent < 0.9 else Fore.RED
    sys.stdout.write(f'\r{Fore.CYAN}{prefix}: {color}{bar} {Fore.WHITE}{percent:.1%} {Fore.CYAN}({current}/{total}){Style.RESET_ALL}')
    sys.stdout.flush()
