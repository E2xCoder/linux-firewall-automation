"""Mirrors how SentinelAI's PythonModuleAdapter loads and drives the class.

SentinelAI config:  adapter: python, module: firewall_manager,
attribute: FirewallManager, init_kwargs: {dry_run: true}  (state_file optional).
"""
import importlib
import subprocess

import pytest

import firewall_manager as fm

REQUIRED = ("block_ip", "unblock_ip", "temporary_block", "list_blocked")
GOOD = "203.0.113.5"


def load_like_adapter(module, attribute, init_kwargs):
    """Same steps as PythonModuleAdapter.__init__."""
    mod = importlib.import_module(module)
    target = getattr(mod, attribute)
    if callable(target) and (isinstance(target, type)
                             or not all(callable(getattr(target, m, None)) for m in REQUIRED)):
        target = target(**init_kwargs)
    missing = [m for m in REQUIRED if not callable(getattr(target, m, None))]
    assert not missing, missing
    return target


@pytest.fixture
def no_real_commands(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a real command was attempted")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(fm, "_run_subprocess", refuse)


def test_module_is_top_level_importable():
    assert importlib.import_module("firewall_manager").__name__ == "firewall_manager"
    assert hasattr(fm, "FirewallManager")


def test_constructor_signature_and_kwargs(tmp_path):
    state = tmp_path / "s.json"
    runner = lambda cmd: True  # noqa: E731
    mgr = fm.FirewallManager(state_file=state, dry_run=True, runner=runner)
    assert mgr.state_file == state and mgr.dry_run is True
    positional = fm.FirewallManager(str(state), False, runner)
    assert positional.dry_run is False


def test_adapter_style_load_with_dry_run_only(tmp_path, monkeypatch, no_real_commands):
    monkeypatch.setenv(fm.ENV_STATE_DIR, str(tmp_path / "state"))
    target = load_like_adapter("firewall_manager", "FirewallManager", {"dry_run": True})
    assert target.block_ip(GOOD) is True
    assert target.is_blocked(GOOD) is True
    assert target.list_blocked() == [GOOD + "/32"]
    assert target.temporary_block("203.0.113.6", 30) is True
    assert target.unblock_ip(GOOD) is True
    assert target.unblock_ip(GOOD) is False
    assert target.is_blocked(GOOD) is False


def test_adapter_style_load_with_state_file(tmp_path, no_real_commands):
    state = tmp_path / "custom.json"
    target = load_like_adapter("firewall_manager", "FirewallManager",
                               {"dry_run": True, "state_file": str(state)})
    assert target.block_ip(GOOD) is True
    assert state.exists()


def test_dry_run_makes_no_runner_call(tmp_path):
    calls = []
    mgr = fm.FirewallManager(state_file=tmp_path / "s.json", dry_run=True,
                             runner=lambda cmd: calls.append(cmd) or True)
    assert mgr.block_ip(GOOD)
    assert mgr.temporary_block("203.0.113.6", 5)
    assert mgr.unblock_ip(GOOD)
    mgr.list_blocked()
    mgr.is_blocked(GOOD)
    mgr.reap()
    assert calls == []


def test_return_types(tmp_path):
    mgr = fm.FirewallManager(state_file=tmp_path / "s.json", dry_run=True)
    assert mgr.block_ip(GOOD) is True
    assert isinstance(mgr.list_blocked(), list)
    assert all(isinstance(item, str) for item in mgr.list_blocked())
    assert isinstance(mgr.is_blocked(GOOD), bool)


@pytest.mark.parametrize("bad", [None, 5, "", "x" * 500, "1.2.3.4\n", object()])
def test_methods_never_raise_on_garbage(tmp_path, bad):
    mgr = fm.FirewallManager(state_file=tmp_path / "s.json", dry_run=True)
    assert mgr.block_ip(bad) is False
    assert mgr.unblock_ip(bad) is False
    assert mgr.temporary_block(bad, 10) is False
    assert mgr.temporary_block(GOOD, [bad]) is False
    assert mgr.is_blocked(bad) is False
    assert mgr.list_blocked() == []
