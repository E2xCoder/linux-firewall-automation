import ipaddress
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

LOG_FILE = "firewall.log"

def log_action(action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {action}\n")

def run_command(command):
    subprocess.run(command)

def valid_port(port):
    if port.isdigit():
        port = int(port)
        if 1 <= port <= 65535:
            return True
    return False

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def enable_firewall():
    run_command(["sudo","ufw","enable"])
    log_action("Firewall enabled")

def disable_firewall():
    run_command(["sudo","ufw","disable"])
    log_action("Firewall disabled")

def allow_port(port):
    run_command(["sudo","ufw","allow",f"{port}/tcp"])
    log_action(f"Allowed port {port}/tcp")

def deny_port(port):
    run_command(["sudo","ufw","deny",f"{port}/tcp"])
    log_action(f"Denied port {port}/tcp")

def block_ip(ip):
    run_command(["sudo","ufw","deny","from",ip])
    log_action(f"Blocked IP {ip}")

def allow_ip(ip):
    run_command(["sudo","ufw","allow","from",ip])
    log_action(f"Allowed IP {ip}")

def reset_firewall():
    run_command(["sudo","ufw","reset"])
    log_action("Firewall reset")

def show_status():
    run_command(["sudo","ufw","status","numbered"])


class FirewallManager:
    """Programmatic API for SentinelAI (adapter: python).

    Provides block_ip, unblock_ip, temporary_block, list_blocked, is_blocked.
    Blocks made through this class are tracked in *state_file* so that
    list_blocked and temporary-block expiry survive restarts. Expired
    temporary blocks are removed lazily on every call, so call
    list_blocked() (or any method) periodically.

    dry_run=True runs no ufw command; it only updates the state file.
    """

    def __init__(self, state_file="firewall_state.json", dry_run=False, runner=None):
        self.state_file = Path(state_file)
        self.dry_run = dry_run
        self._runner = runner or self._ufw

    @staticmethod
    def _ufw(command):
        return subprocess.run(command, check=False).returncode == 0

    def _load(self):
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {ip: exp for ip, exp in data.items()
                if valid_ip(ip) and (exp is None or isinstance(exp, (int, float)))}

    def _save(self, state):
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(self.state_file)

    def _apply(self, command):
        return True if self.dry_run else self._runner(command)

    def _reap(self):
        state = self._load()
        now = time.time()
        expired = [ip for ip, exp in state.items() if exp is not None and exp <= now]
        for ip in expired:
            if self._apply(["sudo", "ufw", "delete", "deny", "from", ip]):
                del state[ip]
                log_action(f"Temporary block expired, unblocked IP {ip}")
        if expired:
            self._save(state)
        return state

    def block_ip(self, ip):
        if not valid_ip(ip):
            return False
        state = self._reap()
        if not self._apply(["sudo", "ufw", "deny", "from", ip]):
            return False
        state[ip] = None
        self._save(state)
        log_action(f"Blocked IP {ip}")
        return True

    def unblock_ip(self, ip):
        if not valid_ip(ip):
            return False
        state = self._reap()
        if ip not in state:
            return False
        if not self._apply(["sudo", "ufw", "delete", "deny", "from", ip]):
            return False
        del state[ip]
        self._save(state)
        log_action(f"Unblocked IP {ip}")
        return True

    def temporary_block(self, ip, duration_seconds):
        if not valid_ip(ip) or duration_seconds <= 0:
            return False
        state = self._reap()
        if not self._apply(["sudo", "ufw", "deny", "from", ip]):
            return False
        state[ip] = time.time() + duration_seconds
        self._save(state)
        log_action(f"Temporarily blocked IP {ip} for {duration_seconds}s")
        return True

    def list_blocked(self):
        return sorted(self._reap())

    def is_blocked(self, ip):
        return ip in self._reap()


def main():
    while True:

        print("""
    === FIREWALL MANAGER ===

    1 Enable Firewall
    2 Disable Firewall
    3 Allow Port
    4 Deny Port
    5 Show Status
    6 Block IP
    7 Allow IP
    8 Reset Firewall
    9 Exit

    """)

        choice = input("Select: ")

        if choice == "1":
            enable_firewall()

        elif choice == "2":
            disable_firewall()

        elif choice == "3":
            port = input("Port: ")

            if valid_port(port):
                allow_port(port)
            else:
                print("Invalid port")

        elif choice == "4":
            port = input("Port: ")

            if valid_port(port):
                deny_port(port)
            else:
                print("Invalid port")

        elif choice == "5":
            show_status()

        elif choice == "6":
            ip = input("IP to block: ")

            if valid_ip(ip):
                block_ip(ip)
            else:
                print("Invalid IP")

        elif choice == "7":
            ip = input("IP to allow: ")

            if valid_ip(ip):
                allow_ip(ip)
            else:
                print("Invalid IP")

        elif choice == "8":
            reset_firewall()

        elif choice == "9":
            break


if __name__ == "__main__":
    main()
