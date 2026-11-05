from conftest import FakeUfw, UFW
import firewall_manager as fm

A = "203.0.113.5"


def test_ufw_inactive_returns_false(make_manager):
    ufw = FakeUfw(active=False)
    mgr = make_manager(ufw)
    assert mgr.block_ip(A) is False
    assert ufw.mutations == []
    assert mgr.list_blocked() == []


def test_unknown_status_output_fails_closed(make_manager):
    mgr = make_manager(lambda c: True)  # plain bool: cannot confirm active
    assert mgr.block_ip(A) is False


def test_sudo_would_prompt(make_manager):
    ufw = FakeUfw(sudo_ok=False)
    mgr = make_manager(ufw)
    assert mgr.block_ip(A) is False
    assert ufw.mutations == []


def test_sudo_n_prefix_and_absolute_ufw(ufw, make_manager):
    assert make_manager(ufw).block_ip(A)
    assert all(c[:3] == ["sudo", "-n", UFW] for c in ufw.calls)


def test_no_sudo_when_root(ufw, make_manager):
    assert make_manager(ufw, use_sudo=False).block_ip(A)
    assert all(c[0] == UFW for c in ufw.calls)


def test_runner_exception_returns_false(make_manager):
    def boom(command):
        raise RuntimeError("x")
    assert make_manager(boom).block_ip(A) is False


def test_subprocess_gets_timeout_and_devnull(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(kwargs)

        class P:
            returncode = 0
            stdout = ""
            stderr = ""
        return P()

    monkeypatch.setattr(fm.subprocess, "run", fake_run)
    assert fm._run_subprocess(["x"], 7)
    assert seen["timeout"] == 7 and seen["stdin"] == fm.subprocess.DEVNULL
    assert seen["check"] is False


def test_subprocess_timeout_is_false(monkeypatch):
    def fake_run(command, **kwargs):
        raise fm.subprocess.TimeoutExpired(command, 1)
    monkeypatch.setattr(fm.subprocess, "run", fake_run)
    assert not fm._run_subprocess(["x"], 1)
