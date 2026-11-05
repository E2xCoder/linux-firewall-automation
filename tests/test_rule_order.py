from conftest import FakeUfw, UFW

A = "203.0.113.5"
A6 = "2001:db8::5"
C4 = A + "/32"
C6 = A6 + "/128"


def test_prepend_when_supported(ufw, make_manager):
    ufw.rules = [ufw.rule("0.0.0.0/0")]
    assert make_manager(ufw).block_ip(A)
    assert ufw.rules[0]["action"] == "deny" and ufw.rules[0]["target"] == C4
    assert ["sudo", "-n", UFW, "prepend", "deny", "from", C4] in ufw.calls


def test_fallback_insert_on_old_ufw(make_manager):
    ufw = FakeUfw(version="0.35.0")
    ufw.rules = [ufw.rule("0.0.0.0/0")]
    assert make_manager(ufw).block_ip(A)
    assert ufw.rules[0]["target"] == C4
    assert ["sudo", "-n", UFW, "insert", "1", "deny", "from", C4] in ufw.calls
    assert not any("prepend" in c for c in ufw.calls)


def test_empty_ruleset_uses_plain_deny(make_manager):
    ufw = FakeUfw(version="0.35.0")
    assert make_manager(ufw).block_ip(A)
    assert ["sudo", "-n", UFW, "deny", "from", C4] in ufw.calls
    assert not any("insert" in c or "prepend" in c for c in ufw.calls)
    assert ufw.denied() == [C4]


def test_unparseable_version_falls_back_to_insert(make_manager):
    ufw = FakeUfw(version="weird")
    ufw.rules = [ufw.rule("0.0.0.0/0")]
    assert make_manager(ufw).block_ip(A)
    assert any(c[3:5] == ["insert", "1"] for c in ufw.calls)


def test_ipv6_insert_before_first_v6_rule(make_manager):
    ufw = FakeUfw(version="0.35.0")
    ufw.rules = [ufw.rule("1.1.1.1"), ufw.rule("::/0"), ufw.rule("2001:db8:1::1")]
    assert make_manager(ufw).block_ip(A6)
    assert [r["target"] for r in ufw.rules] == ["1.1.1.1", C6, "::/0", "2001:db8:1::1"]
    assert any(c[3:5] == ["insert", "2"] for c in ufw.calls)


def test_ipv6_prepend_refused_falls_back(make_manager):
    ufw = FakeUfw(version="0.36.1")
    ufw.rules = [ufw.rule("1.1.1.1"), ufw.rule("::/0")]
    assert make_manager(ufw).block_ip(A6)
    assert [r["target"] for r in ufw.rules] == ["1.1.1.1", C6, "::/0"]


def test_ipv6_appended_when_no_v6_rules(make_manager):
    ufw = FakeUfw(version="0.35.0")
    ufw.rules = [ufw.rule("1.1.1.1")]
    assert make_manager(ufw).block_ip(A6)
    assert ufw.rules[-1]["target"] == C6


def test_failed_rule_returns_false_and_keeps_no_state(make_manager):
    mgr = make_manager(lambda c: False)
    assert mgr.block_ip(A) is False
    assert mgr.list_blocked() == []


def test_unblock_deletes_matching_rule(ufw, make_manager):
    mgr = make_manager(ufw)
    assert mgr.block_ip(A)
    assert mgr.unblock_ip(A)
    assert ["sudo", "-n", UFW, "delete", "deny", "from", C4] in ufw.calls
    assert ufw.denied() == []
    assert mgr.unblock_ip(A) is False
