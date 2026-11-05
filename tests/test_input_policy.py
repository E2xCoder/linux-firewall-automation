import pytest

import firewall_manager as fm
from conftest import FakeUfw

GOOD = "203.0.113.5"


@pytest.mark.parametrize("raw,canonical", [
    ("203.0.113.5", "203.0.113.5/32"),
    ("203.0.113.5/32", "203.0.113.5/32"),
    ("198.51.100.77/24", "198.51.100.0/24"),
    ("2001:DB8::5", "2001:db8::5/128"),
    ("2001:0db8:0000:0000:0000:0000:0000:0005", "2001:db8::5/128"),
    ("2001:db8:abcd::/48", "2001:db8:abcd::/48"),
])
def test_canonicalization(raw, canonical, ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.block_ip(raw) is True
    assert mgr.list_blocked() == [canonical]
    assert canonical in ufw.denied()
    assert mgr.is_blocked(raw) is True


@pytest.mark.parametrize("raw", [
    "", " ", "203.0.113.5 ", "203.0.113.5\n", "203.0.113.5;rm -rf /", "-1.2.3.4",
    "fe80::1%eth0", "2001:db8::1%2", "999.1.1.1", "1.2.3", "not-an-ip", None, 5,
    b"1.2.3.4", ["1.2.3.4"], "1.2.3.4/33", "::ffff:203.0.113.5", "0x7f.1",
    "２０３.0.113.5", "a" * 100,
])
def test_invalid_input_rejected(raw, ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.block_ip(raw) is False
    assert mgr.temporary_block(raw, 60) is False
    assert ufw.mutations == []


@pytest.mark.parametrize("raw", [
    "0.0.0.0", "0.0.0.0/32", "::", "224.0.0.1", "239.255.255.255", "ff02::1",
    "240.0.0.1", "255.255.255.255", "100::1",
])
def test_special_addresses_rejected(raw, ufw, make_manager):
    assert make_manager(ufw).block_ip(raw) is False
    assert ufw.mutations == []


def test_prefix_minimums(ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.block_ip("198.51.0.0/15") is False
    assert mgr.block_ip("0.0.0.0/0") is False
    assert mgr.block_ip("2001:db8::/31") is False
    assert mgr.block_ip("::/0") is False
    assert mgr.block_ip("198.51.0.0/16") is True
    assert mgr.block_ip("2001:db9::/32") is True


def test_prefix_minimum_is_configurable(ufw, make_manager):
    mgr = make_manager(ufw, min_prefix_v4=24, min_prefix_v6=64)
    assert mgr.block_ip("198.51.0.0/16") is False
    assert mgr.block_ip("2001:db8::/48") is False
    assert mgr.block_ip("198.51.100.0/24") is True
    assert mgr.block_ip("2001:db9:1:2::/64") is True


@pytest.mark.parametrize("bad", [0, 33, True, "16", None])
def test_invalid_min_prefix_fails_closed(bad, ufw, make_manager):
    assert make_manager(ufw, min_prefix_v4=bad).block_ip(GOOD) is False


@pytest.mark.parametrize("raw", [
    "127.0.0.1", "127.8.9.10", "::1", "127.0.0.0/8",
    "192.168.1.50",            # own IPv4
    "2001:db8::50",            # own IPv6
    "192.168.1.1",             # IPv4 gateway
    "fe80::1",                 # IPv6 gateway
])
def test_protected_addresses_refused(raw, ufw, make_manager):
    assert make_manager(ufw).block_ip(raw) is False
    assert ufw.mutations == []


def test_cidr_overlap_not_equality(ufw, make_manager):
    mgr = make_manager(ufw, min_prefix_v4=8)
    assert mgr.block_ip("192.168.1.0/24") is False   # contains gateway + own
    assert mgr.block_ip("192.168.0.0/16") is False
    assert mgr.block_ip("127.0.0.0/8") is False
    assert mgr.block_ip("192.168.2.0/24") is True    # adjacent, no overlap
    assert make_manager(ufw, min_prefix_v6=16).block_ip("2001:db8::/32") is False
    assert ufw.denied() == ["192.168.2.0/24"]


def test_ssh_client_protected(monkeypatch, ufw, make_manager):
    monkeypatch.setenv("SSH_CONNECTION", "198.51.100.9 51234 192.168.1.50 22")
    mgr = make_manager(ufw)
    assert mgr.block_ip("198.51.100.9") is False
    assert mgr.block_ip("198.51.100.0/24") is False
    assert mgr.block_ip(GOOD) is True


def test_ssh_client_ipv6_and_mapped(monkeypatch, ufw, make_manager):
    monkeypatch.setenv("SSH_CONNECTION", "2001:db8:9::7 5000 2001:db8::50 22")
    assert make_manager(ufw).block_ip("2001:db8:9::/48") is False
    monkeypatch.setenv("SSH_CONNECTION", "::ffff:198.51.100.9 5000 192.168.1.50 22")
    assert make_manager(ufw).block_ip("198.51.100.9") is False


def test_unparseable_ssh_connection_fails_closed(monkeypatch, ufw, make_manager):
    monkeypatch.setenv("SSH_CONNECTION", "garbage 1 2 3")
    assert make_manager(ufw).block_ip(GOOD) is False


def test_allowlist_argument_and_env(monkeypatch, ufw, make_manager):
    mgr = make_manager(ufw, allowlist=["203.0.113.0/24", "2001:db8:77::/48"])
    assert mgr.block_ip(GOOD) is False
    assert mgr.block_ip("203.0.113.0/25") is False
    assert mgr.block_ip("2001:db8:77::5") is False
    assert mgr.block_ip("203.0.114.1") is True
    monkeypatch.setenv(fm.ENV_ALLOWLIST, "198.51.100.0/24, 192.0.2.7")
    mgr = make_manager(ufw)
    assert mgr.block_ip("198.51.100.200") is False
    assert mgr.block_ip("192.0.2.7") is False


def test_invalid_allowlist_fails_closed(ufw, make_manager):
    assert make_manager(ufw, allowlist=["nonsense"]).block_ip(GOOD) is False
    assert make_manager(ufw, allowlist=5).block_ip(GOOD) is False


def test_gateway_unreadable_fails_closed(fake_host, ufw, make_manager, monkeypatch):
    monkeypatch.setattr(fm.FirewallManager, "PROC_ROUTE", str(fake_host / "missing"))
    mgr = make_manager(ufw)
    assert mgr.block_ip(GOOD) is False
    assert mgr.temporary_block(GOOD, 60) is False
    assert ufw.mutations == []


def test_ipv6_route_unreadable_fails_closed(fake_host, ufw, make_manager, monkeypatch):
    # A directory exists but cannot be read as a file -> not "IPv6 disabled".
    monkeypatch.setattr(fm.FirewallManager, "PROC_ROUTE6", str(fake_host))
    assert make_manager(ufw).block_ip(GOOD) is False


def test_ipv6_disabled_is_not_an_error(fake_host, ufw, make_manager, monkeypatch):
    monkeypatch.setattr(fm.FirewallManager, "PROC_ROUTE6", str(fake_host / "absent"))
    assert make_manager(ufw).block_ip(GOOD) is True


def test_unblock_not_subject_to_protection(ufw, make_manager, tmp_path):
    mgr = make_manager(ufw)
    assert mgr.block_ip(GOOD)
    mgr.allowlist = None
    mgr._allowlist.append(fm.parse_target(GOOD))  # now protected
    assert mgr.unblock_ip(GOOD) is True


def test_dry_run_still_applies_policy(make_manager):
    calls = []
    mgr = make_manager(lambda c: calls.append(c) or True, dry_run=True)
    assert mgr.block_ip("127.0.0.1") is False
    assert mgr.block_ip(GOOD) is True
    assert calls == []
