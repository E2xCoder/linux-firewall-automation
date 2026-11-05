"""UFW firewall automation.

``FirewallManager`` is the programmatic API used by SentinelAI (adapter:
python). The interactive menu lives in ``main()`` and only runs when the file
is executed as a script; importing the module never runs a command.
"""
import contextlib
import errno
import functools
import ipaddress
import json
import logging
import math
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

try:  # POSIX only; the module must still import elsewhere
    import fcntl
except ImportError:  # pragma: no cover - non-Linux
    fcntl = None

ENV_STATE_DIR = "FIREWALL_AUTOMATION_STATE_DIR"
DEFAULT_STATE_SUBDIR = Path(".local") / "state" / "firewall-automation"
DEFAULT_STATE_NAME = "state.json"
DEFAULT_LOG_NAME = "firewall.log"
DEFAULT_LOCK_TIMEOUT = 10.0
MAX_LOG_LINE = 400

_logger = logging.getLogger("firewall_manager")
_PROCESS_LOCK = threading.Lock()

DEFAULT_UFW_PATH = "/usr/sbin/ufw"
DEFAULT_COMMAND_TIMEOUT = 15

# ``ufw prepend`` first appeared in ufw 0.36.
PREPEND_MIN_VERSION = (0, 36)

_SUDO_PROMPT_MARKERS = (
    "a password is required",
    "a terminal is required",
    "no tty present",
)


class FirewallError(Exception):
    """Internal failure; public methods turn it into ``False``."""


def sanitize_log(value):
    """One printable line: control characters (incl. newlines) become '?'."""
    text = value if isinstance(value, str) else repr(value)
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    if len(text) > MAX_LOG_LINE:
        text = text[:MAX_LOG_LINE] + "..."
    return text


def _default_state_dir():
    """Absolute state dir from the environment, else under HOME; None if unusable."""
    configured = os.environ.get(ENV_STATE_DIR)
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else None
    try:
        return Path.home() / DEFAULT_STATE_SUBDIR
    except (RuntimeError, KeyError, OSError):
        return None


def _write_log(path, message):
    line = sanitize_log(message)
    try:
        _logger.info("%s", line)
    except Exception:  # noqa: BLE001 - logging must never change a result
        pass
    if path is None:
        return
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, f"{datetime.now().isoformat(timespec='seconds')} - {line}\n"
                     .encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001
        pass


def log_action(action):
    state_dir = _default_state_dir()
    _write_log(state_dir / DEFAULT_LOG_NAME if state_dir else None, action)


def run_command(command):
    subprocess.run(command)


def valid_port(port):
    if port.isdigit():
        port = int(port)
        if 1 <= port <= 65535:
            return True
    return False


_ADDRESS_CHARS = frozenset("0123456789abcdefABCDEF:./")
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def parse_target(value):
    """Canonical ``ip_network`` for an IPv4/IPv6 address or CIDR, else None.

    Pure format validation: rejects non-strings, whitespace/control characters,
    zone IDs (``%``), and IPv4-mapped IPv6. Host bits are masked, so
    ``10.0.0.5/24`` becomes ``10.0.0.0/24``.
    """
    if not isinstance(value, str) or not 0 < len(value) <= 64:
        return None
    if not set(value) <= _ADDRESS_CHARS:
        return None
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if net.version == 6 and net.overlaps(_V4_MAPPED):
        return None
    return net


def valid_ip(ip):
    return parse_target(ip) is not None


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

    def __init__(self, state_file=None, dry_run=False, runner=None, *,
                 state_dir=None, log_file=None, ufw_path=DEFAULT_UFW_PATH,
                 use_sudo=None, command_timeout=DEFAULT_COMMAND_TIMEOUT,
                 lock_timeout=DEFAULT_LOCK_TIMEOUT, interactive=False):
        self.dry_run = dry_run
        self.ufw_path = ufw_path
        self.command_timeout = command_timeout
        self.lock_timeout = lock_timeout
        self.interactive = interactive
        self.use_sudo = (not _is_root()) if use_sudo is None else bool(use_sudo)
        self._runner = runner
        self._prepend_ok = None
        self._clock = time.time
        self._reaper = None
        self._reaper_stop = threading.Event()
        self.state_dir, self.state_file, self.log_file = self._resolve_paths(
            state_dir, state_file, log_file)

    @staticmethod
    def _resolve_paths(state_dir, state_file, log_file):
        """Never raises; an unusable location becomes None (methods then fail)."""
        try:
            if state_dir is not None:
                base = Path(state_dir)
                base = base if base.is_absolute() else None
            else:
                base = _default_state_dir()
            if state_file is None:
                state = base / DEFAULT_STATE_NAME if base else None
            else:
                state = Path(state_file)
                if not state.is_absolute():
                    state = base / state if base else None
            if log_file is not None:
                log = Path(log_file)
            elif base is not None:
                log = base / DEFAULT_LOG_NAME
            else:
                log = state.parent / DEFAULT_LOG_NAME if state else None
            return base, state, log
        except Exception:  # noqa: BLE001
            return None, None, None

    # -- logging -----------------------------------------------------------

    def _log(self, message):
        _write_log(self.log_file, message)

    # -- locking -----------------------------------------------------------

    @contextlib.contextmanager
    def _locked(self):
        """Thread lock plus an flock on ``<state>.lock`` (POSIX)."""
        path = self.state_file
        if path is None:
            raise FirewallError(
                "no usable state location (HOME unset or state dir not absolute)")
        deadline = time.monotonic() + self.lock_timeout
        if not _PROCESS_LOCK.acquire(timeout=self.lock_timeout):
            raise FirewallError("lock timeout (another thread holds the state lock)")
        fd = None
        try:
            try:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if fcntl is not None:
                    fd = os.open(str(path.with_name(path.name + ".lock")),
                                 os.O_RDWR | os.O_CREAT, 0o600)
                    while True:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except OSError as exc:
                            if exc.errno not in (errno.EAGAIN, errno.EACCES):
                                raise
                            if time.monotonic() >= deadline:
                                raise FirewallError(
                                    "lock timeout (another process holds the state lock)")
                            time.sleep(0.05)
            except OSError as exc:
                raise FirewallError(f"cannot lock state: {exc}") from exc
            yield
        finally:
            if fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    os.close(fd)
            _PROCESS_LOCK.release()

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
        """Return {canonical network: expiry or None}. Raises FirewallError."""
        try:
            raw = self.state_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise FirewallError(f"cannot read state file: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise FirewallError(
                "state file is corrupt; refusing to overwrite it") from exc
        if not isinstance(data, dict):
            raise FirewallError("state file is corrupt; refusing to overwrite it")
        if data.get("version") == 1:
            blocks = data.get("blocks")
            if not isinstance(blocks, dict):
                raise FirewallError("state file is corrupt; refusing to overwrite it")
        else:  # legacy flat {ip: expiry}
            blocks = data
        state = {}
        for key, expiry in blocks.items():
            net = parse_target(key)
            valid_expiry = expiry is None or (
                isinstance(expiry, (int, float)) and not isinstance(expiry, bool)
                and math.isfinite(expiry))
            if net is None or not valid_expiry:
                self._log(f"Ignoring invalid state entry {key!r}")
                continue
            state[str(net)] = expiry
        return state

    def _save(self, state):
        path = self.state_file
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        payload = json.dumps({"version": 1, "blocks": state}, sort_keys=True)
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(tmp), str(path))
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(str(tmp))
            raise FirewallError(f"cannot save state file: {exc}") from exc

    def _apply_rule(self, target):
        return True if self.dry_run else self._add_rule(target)

    def _remove_rule(self, target):
        return True if self.dry_run else self._delete_rule(target)

    def _reap_locked(self, state):
        """Remove expired blocks from *state* and ufw. Returns (removed, failed)."""
        now = self._clock()
        expired = [k for k, exp in state.items() if exp is not None and exp <= now]
        removed = failed = 0
        for key in expired:
            if self._remove_rule(key):
                del state[key]
                removed += 1
                self._log(f"Temporary block expired, unblocked {key}")
            else:
                failed += 1
        if removed:
            try:
                self._save(state)
            except FirewallError as exc:
                self._log(str(exc))
                failed += removed
        return removed, failed

    # -- public API --------------------------------------------------------

    def _guarded(default):
        """Public methods never raise: any failure returns *default*."""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(self, *args, **kwargs):
                try:
                    return func(self, *args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    with contextlib.suppress(Exception):
                        self._log(f"{func.__name__} failed: {exc}")
                    return default() if callable(default) else default
            return wrapper
        return decorator

    def _block(self, ip, duration):
        net = parse_target(ip)
        if net is None:
            self._log(f"Rejected invalid address {ip!r}")
            return False
        key = str(net)
        expiry = None if duration is None else self._clock() + duration
        with self._locked():
            state = self._load()
            self._reap_locked(state)
            if key in state:
                old = state[key]
                new = None if (expiry is None or old is None) else max(old, expiry)
                if new != old:
                    state[key] = new
                    self._save(state)
                self._log(f"Block already present for {key}")
                return True
            if not self._apply_rule(key):
                return False
            state[key] = expiry
            try:
                self._save(state)
            except FirewallError as exc:
                undone = self._remove_rule(key)
                self._log(f"{exc}; rule for {key} "
                          f"{'rolled back' if undone else 'COULD NOT BE ROLLED BACK'}")
                return False
        if duration is None:
            self._log(f"Blocked {key}")
        else:
            self._log(f"Temporarily blocked {key} for {duration}s")
        return True

    @_guarded(False)
    def block_ip(self, ip):
        return self._block(ip, None)

    @_guarded(False)
    def temporary_block(self, ip, duration_seconds):
        if (isinstance(duration_seconds, bool)
                or not isinstance(duration_seconds, (int, float))
                or not math.isfinite(duration_seconds) or duration_seconds <= 0):
            return False
        return self._block(ip, duration_seconds)

    @_guarded(False)
    def unblock_ip(self, ip):
        net = parse_target(ip)
        if net is None:
            return False
        key = str(net)
        with self._locked():
            state = self._load()
            self._reap_locked(state)
            if key not in state:
                return False
            if not self._remove_rule(key):
                return False
            old = state.pop(key)
            try:
                self._save(state)
            except FirewallError as exc:
                restored = self._apply_rule(key)
                self._log(f"{exc}; rule for {key} "
                          f"{'restored' if restored else 'COULD NOT BE RESTORED'}")
                return False
        self._log(f"Unblocked {key}")
        return True

    @_guarded(list)
    def list_blocked(self):
        with self._locked():
            state = self._load()
            self._reap_locked(state)
            return sorted(state)

    @_guarded(False)
    def is_blocked(self, ip):
        net = parse_target(ip)
        if net is None:
            return False
        with self._locked():
            state = self._load()
            self._reap_locked(state)
        for key in state:
            blocked = ipaddress.ip_network(key)
            if blocked.version == net.version and net.subnet_of(blocked):
                return True
        return False

    del _guarded


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
