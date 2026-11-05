import json
import subprocess
import sys
import threading
import time

import firewall_manager as fm
from conftest import FakeUfw, ROOT

A = "203.0.113.5"
B = "203.0.113.6"
C4 = A + "/32"


def test_temporary_block_expires_and_reap_removes_rule(ufw, make_manager):
    mgr = make_manager(ufw)
    now = [1000.0]
    mgr._clock = lambda: now[0]
    assert mgr.temporary_block(A, 60)
    assert mgr.block_ip(B)
    assert mgr.reap() is True            # nothing expired yet
    assert ufw.denied() == [B + "/32", C4]
    now[0] = 1061.0
    assert mgr.reap() is True
    assert ufw.denied() == [B + "/32"]
    assert json.loads(mgr.state_file.read_text())["blocks"] == {B + "/32": None}


def test_lazy_reap_on_other_calls(ufw, make_manager):
    mgr = make_manager(ufw)
    now = [0.0]
    mgr._clock = lambda: now[0]
    assert mgr.temporary_block(A, 10)
    assert mgr.is_blocked(A)
    now[0] = 11.0
    assert mgr.is_blocked(A) is False
    assert mgr.list_blocked() == []
    assert ufw.denied() == []


def test_reap_failure_keeps_entry_and_returns_false(make_manager):
    ufw = FakeUfw()
    mgr = make_manager(ufw)
    now = [0.0]
    mgr._clock = lambda: now[0]
    assert mgr.temporary_block(A, 10)
    now[0] = 11.0
    mgr._runner = lambda c: False          # ufw delete now fails
    assert mgr.reap() is False
    assert C4 in json.loads(mgr.state_file.read_text())["blocks"]
    mgr._runner = ufw
    assert mgr.reap() is True
    assert ufw.denied() == []


def test_reblock_semantics(ufw, make_manager):
    mgr = make_manager(ufw)
    now = [0.0]
    mgr._clock = lambda: now[0]
    assert mgr.temporary_block(A, 10)
    assert mgr.temporary_block(A, 100)     # extends
    assert json.loads(mgr.state_file.read_text())["blocks"][C4] == 100.0
    assert mgr.block_ip(A)                 # becomes permanent
    assert mgr.temporary_block(A, 5)       # never downgrades
    assert json.loads(mgr.state_file.read_text())["blocks"][C4] is None
    assert len(ufw.denied()) == 1


def test_invalid_durations(ufw, make_manager):
    mgr = make_manager(ufw)
    for bad in (0, -5, True, float("nan"), float("inf"), "60", None):
        assert mgr.temporary_block(A, bad) is False
    assert ufw.mutations == []


def test_reap_in_dry_run_runs_no_command(make_manager):
    calls = []
    mgr = make_manager(lambda c: calls.append(c) or True, dry_run=True)
    now = [0.0]
    mgr._clock = lambda: now[0]
    assert mgr.temporary_block(A, 1)
    now[0] = 5.0
    assert mgr.reap() is True
    assert mgr.list_blocked() == []
    assert calls == []


def test_constructor_does_not_start_reaper(ufw, make_manager):
    before = threading.active_count()
    mgr = make_manager(ufw)
    assert threading.active_count() == before
    assert mgr._reaper is None


def test_start_stop_reaper(ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.temporary_block(A, 0.05)
    assert mgr.start_reaper(0.05) is True
    assert mgr.start_reaper(0.05) is True   # idempotent
    deadline = time.time() + 5
    while time.time() < deadline and ufw.denied():
        time.sleep(0.05)
    assert ufw.denied() == []
    assert mgr.stop_reaper() is True
    assert mgr._reaper is None
    assert mgr.stop_reaper() is True


def test_start_reaper_rejects_bad_interval(ufw, make_manager):
    mgr = make_manager(ufw)
    for bad in (0, -1, True, float("nan"), "5"):
        assert mgr.start_reaper(bad) is False


def test_cli_reap_dry_run(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"version": 1, "blocks": {C4: 1.0, B + "/32": None}}))
    proc = subprocess.run(
        [sys.executable, str(fm.__file__), "--reap", "--dry-run",
         "--state-file", str(state)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(state.read_text())["blocks"] == {B + "/32": None}


def test_cli_reap_exit_code_on_failure(tmp_path):
    bad = tmp_path / "file"
    bad.write_text("x")
    proc = subprocess.run(
        [sys.executable, str(fm.__file__), "--reap", "--dry-run",
         "--state-file", str(bad / "state.json")],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 1


def test_menu_still_works(monkeypatch, capsys):
    answers = iter(["6", "999.9.9.9", "3", "abc", "9"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert fm.main([]) == 0
    out = capsys.readouterr().out
    assert "FIREWALL MANAGER" in out
    assert "Invalid IP" in out and "Invalid port" in out
