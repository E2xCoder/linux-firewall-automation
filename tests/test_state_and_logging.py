import json
import subprocess
import sys
import threading
from pathlib import Path

import firewall_manager as fm
from conftest import FakeUfw, ROOT

A = "203.0.113.5"
C4 = A + "/32"


def test_import_does_not_start_menu():
    proc = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {ROOT!r}); import firewall_manager"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    assert "FIREWALL MANAGER" not in proc.stdout


def test_state_dir_precedence(tmp_path, monkeypatch):
    env_dir = tmp_path / "env"
    arg_dir = tmp_path / "arg"
    monkeypatch.setenv(fm.ENV_STATE_DIR, str(env_dir))
    assert fm.FirewallManager(state_dir=arg_dir).state_file == arg_dir / "state.json"
    assert fm.FirewallManager().state_file == env_dir / "state.json"
    monkeypatch.delenv(fm.ENV_STATE_DIR)
    monkeypatch.setattr(fm.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    expected = tmp_path / "home" / ".local" / "state" / "firewall-automation"
    assert fm.FirewallManager().state_dir == expected


def test_relative_state_dir_is_rejected(tmp_path):
    mgr = fm.FirewallManager(state_dir="relative/dir", runner=FakeUfw())
    assert mgr.block_ip(A) is False


def test_home_unset_never_raises(monkeypatch):
    monkeypatch.delenv(fm.ENV_STATE_DIR, raising=False)

    def no_home(cls):
        raise RuntimeError("Could not determine home directory.")
    monkeypatch.setattr(fm.Path, "home", classmethod(no_home))
    mgr = fm.FirewallManager(runner=FakeUfw(), use_sudo=True)
    assert mgr.block_ip(A) is False
    assert mgr.unblock_ip(A) is False
    assert mgr.temporary_block(A, 60) is False
    assert mgr.list_blocked() == []
    assert mgr.is_blocked(A) is False


def test_unwritable_state_path_never_raises(tmp_path, make_manager):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    ufw = FakeUfw()
    mgr = make_manager(ufw, state_file=blocker / "sub" / "state.json")
    assert mgr.block_ip(A) is False
    assert ufw.mutations == []


def test_unwritable_log_does_not_change_result(tmp_path, make_manager):
    ufw = FakeUfw()
    mgr = make_manager(ufw, log_file=tmp_path)  # a directory: cannot be opened
    assert mgr.block_ip(A) is True
    assert mgr.is_blocked(A) is True


def test_save_failure_rolls_rule_back(ufw, make_manager):
    mgr = make_manager(ufw)

    def broken(state):
        raise fm.FirewallError("disk full")
    mgr._save = broken
    assert mgr.block_ip(A) is False
    assert ufw.denied() == []
    assert any(c[3:] == ["delete", "deny", "from", C4] for c in ufw.calls)


def test_save_failure_on_unblock_restores_rule(ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.block_ip(A)
    mgr._save = lambda state: (_ for _ in ()).throw(fm.FirewallError("disk full"))
    assert mgr.unblock_ip(A) is False
    assert ufw.denied() == [C4]
    assert A in " ".join(mgr._load())


def test_corrupt_state_is_not_overwritten(tmp_path, ufw, make_manager):
    state = tmp_path / "state.json"
    state.write_text("{not json")
    mgr = make_manager(ufw, state_file=state)
    assert mgr.block_ip(A) is False
    assert state.read_text() == "{not json"
    assert ufw.mutations == []


def test_legacy_state_format_is_read(tmp_path, ufw, make_manager):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({A: None}))
    mgr = make_manager(ufw, state_file=state)
    assert mgr.list_blocked() == [C4]


def test_lock_timeout_returns_false(ufw, make_manager):
    mgr = make_manager(ufw, lock_timeout=0.2)
    assert fm._PROCESS_LOCK.acquire(timeout=1)
    try:
        assert mgr.block_ip(A) is False
        assert mgr.list_blocked() == []
    finally:
        fm._PROCESS_LOCK.release()
    assert mgr.block_ip(A) is True


def test_concurrent_writers_do_not_corrupt_state(tmp_path):
    ufw = FakeUfw()
    state = tmp_path / "state.json"
    ufw_lock = threading.Lock()

    def locked_runner(command):
        with ufw_lock:
            return ufw(command)

    def worker(base):
        mgr = fm.FirewallManager(state_file=state, runner=locked_runner,
                                 use_sudo=True)
        for i in range(15):
            assert mgr.block_ip(f"198.51.{base}.{i + 1}")

    threads = [threading.Thread(target=worker, args=(b,)) for b in (100, 101)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    data = json.loads(state.read_text())
    assert len(data["blocks"]) == 30
    assert len(ufw.denied()) == 30


def test_sanitize_log_strips_control_characters():
    out = fm.sanitize_log("ok\nFORGED line\r\x1b[31m\x00 end")
    assert "\n" not in out and "\r" not in out and "\x1b" not in out
    assert "\x00" not in out and " " not in out
    assert out.startswith("ok?FORGED line")


def test_log_injection_via_ip_is_neutralised(tmp_path, ufw, make_manager):
    log = tmp_path / "fw.log"
    mgr = make_manager(ufw, log_file=log)
    assert mgr.block_ip("1.2.3.4\n2030-01-01 - Unblocked everything") is False
    lines = Path(log).read_text().splitlines()
    assert lines and all(" - " in line for line in lines)
    assert len(lines) == 1
    assert "\x1b" not in Path(log).read_text()
