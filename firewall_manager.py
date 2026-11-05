"""UFW firewall automation.

``FirewallManager`` is the programmatic API used by SentinelAI (adapter:
python). The interactive menu lives in ``main()`` and only runs when the file
is executed as a script; importing the module never runs a command.
"""
import ipaddress
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

LOG_FILE = "firewall.log"

DEFAULT_UFW_PATH = "/usr/sbin/ufw"
DEFAULT_COMMAND_TIMEOUT = 15

# ``ufw prepend`` first appeared in ufw 0.36.
PREPEND_MIN_VERSION = (0, 36)

_SUDO_PROMPT_MARKERS = (
    "a password is required",
    "a terminal is required",
    "no tty present",
)


def log_action(action):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} - {action}\n")
    except OSError:
        pass


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
    run_command(["sudo", "ufw", "enable"])
    log_action("Firewall enabled")


def disable_firewall():
    run_command(["sudo", "ufw", "disable"])
    log_action("Firewall disabled")


def allow_port(port):
    run_command(["sudo", "ufw", "allow", f"{port}/tcp"])
    log_action(f"Allowed port {port}/tcp")


def deny_port(port):
    run_command(["sudo", "ufw", "deny", f"{port}/tcp"])
    log_action(f"Denied port {port}/tcp")


def allow_ip(ip):
    run_command(["sudo", "ufw", "allow", "from", ip])
    log_action(f"Allowed IP {ip}")


def reset_firewall():
    run_command(["sudo", "ufw", "reset"])
    log_action("Firewall reset")


def show_status():
    run_command(["sudo", "ufw", "status", "numbered"])


class CommandResult:
    """Result of one command: truthy when it succeeded.

    A custom ``runner`` may return a plain bool or a ``CommandResult``. Only a
    ``CommandResult`` (or any object with ``stdout``/``stderr`` attributes)
    carries the output needed to confirm that ufw is active and to pick the
    rule-insertion strategy.
    """

    __slots__ = ("ok", "stdout", "stderr")

    def __init__(self, ok, stdout="", stderr=""):
        self.ok = bool(ok)
        self.stdout = stdout or ""
        self.stderr = stderr or ""

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return f"CommandResult(ok={self.ok!r})"


def _run_subprocess(command, timeout, interactive=False):
    try:
        proc = subprocess.run(
            command,
            stdin=None if interactive else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(False, "", "command timed out")
    except (OSError, ValueError) as exc:
        return CommandResult(False, "", str(exc))
    return CommandResult(proc.returncode == 0, proc.stdout, proc.stderr)


def _is_root():
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


class FirewallManager:
    """Programmatic API for SentinelAI (adapter: python).

    Provides block_ip, unblock_ip, temporary_block, list_blocked, is_blocked.
    Blocks made through this class are tracked in *state_file* so that
    list_blocked and temporary-block expiry survive restarts.

    dry_run=True runs no ufw command; it only updates the state file.

    ``runner(command_list) -> bool`` receives the full command, including the
    ``sudo -n`` prefix when one is used.
    """

    def __init__(self, state_file="firewall_state.json", dry_run=False,
                 runner=None, *, ufw_path=DEFAULT_UFW_PATH, use_sudo=None,
                 command_timeout=DEFAULT_COMMAND_TIMEOUT, interactive=False):
        self.state_file = Path(state_file)
        self.dry_run = dry_run
        self.ufw_path = ufw_path
        self.command_timeout = command_timeout
        self.interactive = interactive
        self.use_sudo = (not _is_root()) if use_sudo is None else bool(use_sudo)
        self._runner = runner
        self._prepend_ok = None

    # -- logging -----------------------------------------------------------

    def _log(self, message):
        log_action(message)

    # -- command execution -------------------------------------------------

    def _command(self, *args):
        prefix = []
        if self.use_sudo:
            prefix = ["sudo"] if self.interactive else ["sudo", "-n"]
        return prefix + [self.ufw_path] + list(args)

    def _exec(self, *args):
        """Run one ufw command. Returns (ok, stdout); never raises."""
        command = self._command(*args)
        try:
            if self._runner is not None:
                result = self._runner(command)
            else:
                result = _run_subprocess(command, self.command_timeout,
                                         self.interactive)
        except Exception as exc:  # noqa: BLE001 - runner is untrusted
            self._log(f"ufw command failed to run ({args[0]}): {exc}")
            return False, ""
        ok = bool(result)
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        if not ok:
            text = f"{stdout}\n{stderr}".lower()
            if any(marker in text for marker in _SUDO_PROMPT_MARKERS):
                self._log(
                    "sudo would prompt for a password; refusing to hang. "
                    f"Add a NOPASSWD sudoers entry for {self.ufw_path} "
                    "(see README)")
            else:
                self._log(f"ufw {args[0]} failed")
        return ok, (stdout if isinstance(stdout, str) else "")

    # -- ufw probes --------------------------------------------------------

    def _status(self):
        """Return (active, rules) from ``ufw status numbered``, or None."""
        ok, out = self._exec("status", "numbered")
        if not ok:
            return None
        active = re.search(r"^Status:\s*active\b", out, re.M | re.I) is not None
        rules = []
        for line in out.splitlines():
            m = re.match(r"\s*\[\s*(\d+)\]", line)
            if m:
                rules.append((int(m.group(1)), "(v6)" in line))
        return active, rules

    def _supports_prepend(self):
        if self._prepend_ok is not None:
            return self._prepend_ok
        ok, out = self._exec("version")
        if not ok:
            return False
        m = re.search(r"\bufw\s+(\d+)\.(\d+)", out)
        if not m:
            return False
        self._prepend_ok = (int(m.group(1)), int(m.group(2))) >= PREPEND_MIN_VERSION
        return self._prepend_ok

    # -- rules -------------------------------------------------------------

    def _add_rule(self, target):
        """Apply ``deny from target`` as the first rule. True on success."""
        status = self._status()
        if status is None:
            return False
        active, rules = status
        if not active:
            self._log("ufw is inactive; rule would have no effect. "
                      "Enable it first with 'ufw enable'")
            return False
        if not rules:
            return self._exec("deny", "from", target)[0]
        if self._supports_prepend():
            return self._exec("prepend", "deny", "from", target)[0]
        if self._exec("insert", "1", "deny", "from", target)[0]:
            return True
        is_v6 = ":" in target
        if not is_v6:
            return False
        # ufw refuses an IPv6 rule ahead of IPv4 rules: go before the first
        # IPv6 rule, or append when there is none (then nothing precedes it).
        v6_numbers = [number for number, v6 in rules if v6]
        if v6_numbers:
            return self._exec("insert", str(min(v6_numbers)),
                              "deny", "from", target)[0]
        self._log("IPv6 rule appended; no IPv6 rule can precede it")
        return self._exec("deny", "from", target)[0]

    def _delete_rule(self, target):
        return self._exec("delete", "deny", "from", target)[0]

    # -- state -------------------------------------------------------------

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

    def _apply_rule(self, target):
        return True if self.dry_run else self._add_rule(target)

    def _remove_rule(self, target):
        return True if self.dry_run else self._delete_rule(target)

    def _reap(self):
        state = self._load()
        now = time.time()
        expired = [ip for ip, exp in state.items() if exp is not None and exp <= now]
        for ip in expired:
            if self._remove_rule(ip):
                del state[ip]
                self._log(f"Temporary block expired, unblocked IP {ip}")
        if expired:
            self._save(state)
        return state

    # -- public API --------------------------------------------------------

    def block_ip(self, ip):
        if not valid_ip(ip):
            return False
        state = self._reap()
        if not self._apply_rule(ip):
            return False
        state[ip] = None
        self._save(state)
        self._log(f"Blocked IP {ip}")
        return True

    def unblock_ip(self, ip):
        if not valid_ip(ip):
            return False
        state = self._reap()
        if ip not in state:
            return False
        if not self._remove_rule(ip):
            return False
        del state[ip]
        self._save(state)
        self._log(f"Unblocked IP {ip}")
        return True

    def temporary_block(self, ip, duration_seconds):
        if not valid_ip(ip) or duration_seconds <= 0:
            return False
        state = self._reap()
        if not self._apply_rule(ip):
            return False
        state[ip] = time.time() + duration_seconds
        self._save(state)
        self._log(f"Temporarily blocked IP {ip} for {duration_seconds}s")
        return True

    def list_blocked(self):
        return sorted(self._reap())

    def is_blocked(self, ip):
        return ip in self._reap()


MENU = """
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

"""


def main():
    manager = FirewallManager(interactive=True)
    while True:
        print(MENU)
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
                if not manager.block_ip(ip):
                    print("Block failed (see firewall.log)")
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
