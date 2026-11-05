import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import firewall_manager as fm  # noqa: E402

UFW = "/usr/sbin/ufw"


class FakeUfw:
    """In-memory ufw used as the injected runner. Never runs a real command."""

    def __init__(self, active=True, version="0.36.1", rules=None,
                 sudo_ok=True, strict_v6=True):
        self.active = active
        self.version = version
        self.rules = list(rules or [])  # dicts: action, target, v6
        self.sudo_ok = sudo_ok
        self.strict_v6 = strict_v6
        self.calls = []

    # helpers ----------------------------------------------------------
    @staticmethod
    def rule(target, action="allow"):
        return {"action": action, "target": target, "v6": ":" in target}

    @property
    def mutations(self):
        verbs = ("deny", "allow", "insert", "prepend", "delete")
        out = []
        for call in self.calls:
            args = self._strip(call)
            if args and args[0] in verbs:
                out.append(call)
        return out

    def denied(self):
        return [r["target"] for r in self.rules if r["action"] == "deny"]

    @staticmethod
    def _strip(command):
        cmd = list(command)
        if cmd[:2] == ["sudo", "-n"]:
            cmd = cmd[2:]
        elif cmd[:1] == ["sudo"]:
            cmd = cmd[1:]
        return cmd[1:] if cmd and cmd[0] == UFW else cmd

    def _insert(self, index, rule):
        if self.strict_v6 and rule["v6"] and any(
                not r["v6"] for r in self.rules[index:]):
            return fm.CommandResult(
                False, "", "ERROR: Cannot insert IPv6 rule before IPv4 rules")
        self.rules.insert(index, rule)
        return fm.CommandResult(True)

    # runner -----------------------------------------------------------
    def __call__(self, command):
        self.calls.append(list(command))
        if command[:2] == ["sudo", "-n"] and not self.sudo_ok:
            return fm.CommandResult(False, "", "sudo: a password is required")
        args = self._strip(command)
        if args == ["version"]:
            return fm.CommandResult(
                True, f"ufw {self.version}\nCopyright 2008-2023 Canonical Ltd.\n")
        if args == ["status", "numbered"]:
            lines = [f"Status: {'active' if self.active else 'inactive'}"]
            if self.active and self.rules:
                lines.append("")
                for i, r in enumerate(self.rules, 1):
                    suffix = " (v6)" if r["v6"] else ""
                    lines.append(
                        f"[{i:>2}] Anywhere{suffix}    {r['action'].upper()} IN    {r['target']}")
            return fm.CommandResult(True, "\n".join(lines) + "\n")
        if args[:1] == ["prepend"]:
            if tuple(int(x) for x in self.version.split(".")[:2]) < (0, 36):
                return fm.CommandResult(False, "", "ERROR: Invalid syntax")
            return self._insert(0, self.rule(args[-1], args[1]))
        if args[:1] == ["insert"]:
            pos = int(args[1])
            if pos < 1 or pos > len(self.rules):
                return fm.CommandResult(False, "", f"ERROR: Invalid position '{pos}'")
            return self._insert(pos - 1, self.rule(args[-1], args[2]))
        if args[:1] in (["deny"], ["allow"]):
            self.rules.append(self.rule(args[-1], args[0]))
            return fm.CommandResult(True)
        if args[:1] == ["delete"]:
            for r in self.rules:
                if r["action"] == args[1] and r["target"] == args[-1]:
                    self.rules.remove(r)
                    break
            return fm.CommandResult(True)
        return fm.CommandResult(False, "", "ERROR: unsupported in fake")


@pytest.fixture
def ufw():
    return FakeUfw()


@pytest.fixture
def make_manager(tmp_path):
    def factory(runner, **kwargs):
        kwargs.setdefault("state_file", tmp_path / "state.json")
        kwargs.setdefault("use_sudo", True)
        return fm.FirewallManager(runner=runner, **kwargs)
    return factory
