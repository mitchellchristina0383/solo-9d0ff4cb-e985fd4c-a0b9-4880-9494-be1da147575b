from __future__ import annotations

import pytest

from app.rules import RuleValidationError, RuleSetSnapshot, build_snapshot, validate_rules
from app.storage import Storage


def rules(*items):
    snapshot_rules = []
    for i, item in enumerate(items, 1):
        snapshot_rules.append({"index": i, **item})
    return snapshot_rules


def make_snapshot(rule_dicts, revision=1):
    normalized = validate_rules(rule_dicts)
    return build_snapshot(revision, "2026-01-01T00:00:00Z", "", normalized)


def test_requires_all_dimensions():
    snapshot = make_snapshot(
        [{"host": "api.example.com", "ports": [443], "networks": ["10.0.0.0/8"]}]
    )
    assert snapshot.admit("api.example.com", 443, ["10.1.2.3"]).allowed
    assert not snapshot.admit("api.example.com", 8443, ["10.1.2.3"]).allowed
    assert not snapshot.admit("other.example.com", 443, ["10.1.2.3"]).allowed
    assert not snapshot.admit("api.example.com", 443, ["192.168.1.1"]).allowed


def test_wildcard_matches_subdomains_only():
    snapshot = make_snapshot([{"host": "*.example.com", "ports": [443], "networks": ["0.0.0.0/0"]}])
    assert snapshot.admit("a.example.com", 443, ["1.2.3.4"]).allowed
    assert snapshot.admit("a.b.example.com", 443, ["1.2.3.4"]).allowed
    assert not snapshot.admit("example.com", 443, ["1.2.3.4"]).allowed
    assert not snapshot.admit("badexample.com", 443, ["1.2.3.4"]).allowed


def test_every_resolved_address_must_be_permitted():
    snapshot = make_snapshot([{"host": "x.test", "ports": [443], "networks": ["10.0.0.0/8"]}])
    decision = snapshot.admit("x.test", 443, ["10.0.0.1", "172.16.0.1"])
    assert not decision.allowed
    assert decision.reason == "address_not_allowed"
    assert "172.16.0.1" in decision.detail


def test_ip_literal_target_requires_matching_rule_host():
    snapshot = make_snapshot([{"host": "10.1.2.3", "ports": [80], "networks": ["10.0.0.0/8"]}])
    assert snapshot.admit("10.1.2.3", 80, ["10.1.2.3"]).allowed
    assert not snapshot.admit("10.1.2.4", 80, ["10.1.2.4"]).allowed


def test_ports_are_per_rule_not_global():
    snapshot = make_snapshot(
        [
            {"host": "a.test", "ports": [443], "networks": ["10.0.0.0/8"]},
            {"host": "b.test", "ports": [80], "networks": ["10.0.0.0/8"]},
        ]
    )
    assert snapshot.admit("a.test", 443, ["10.0.0.1"]).allowed
    assert snapshot.admit("b.test", 80, ["10.0.0.1"]).allowed
    assert not snapshot.admit("a.test", 80, ["10.0.0.1"]).allowed


def test_empty_rules_denies_everything():
    snapshot = make_snapshot([])
    assert not snapshot.admit("anything.test", 443, ["10.0.0.1"]).allowed


def test_non_ipv4_resolution_is_denied():
    snapshot = make_snapshot([{"host": "x.test", "ports": [443], "networks": ["0.0.0.0/0"]}])
    decision = snapshot.admit("x.test", 443, ["::1"])
    assert not decision.allowed
    assert decision.reason == "non_ipv4_address"


@pytest.mark.parametrize(
    "bad",
    [
        [{"host": "a.test", "ports": [], "networks": ["10.0.0.0/8"]}],
        [{"host": "a.test", "ports": [0], "networks": ["10.0.0.0/8"]}],
        [{"host": "a.test", "ports": [70000], "networks": ["10.0.0.0/8"]}],
        [{"host": "a.test", "ports": [443], "networks": []}],
        [{"host": "a.test", "ports": [443], "networks": ["::/0"]}],
        [{"host": "a.test", "ports": [443], "networks": ["not-a-net"]}],
        [{"host": "", "ports": [443], "networks": ["10.0.0.0/8"]}],
        [{"host": "*example.com", "ports": [443], "networks": ["10.0.0.0/8"]}],
        [{"host": "a.test", "ports": [443], "networks": ["10.0.0.0/8"], "extra": 1}],
        ["not-an-object"],
        {"host": "a.test"},
    ],
)
def test_invalid_rule_sets_are_rejected(bad):
    with pytest.raises(RuleValidationError):
        validate_rules(bad)


def test_rules_are_normalized_before_storage():
    normalized = validate_rules(
        [
            {
                "host": "API.Example.COM.",
                "ports": ["443", 443, 80],
                "networks": ["10.1.2.3/8", "10.0.0.0/8"],
                "description": "  prod  ",
            }
        ]
    )
    assert normalized == [
        {
            "host": "api.example.com",
            "ports": [80, 443],
            "networks": ["10.0.0.0/8"],
            "description": "prod",
        }
    ]


def test_rule_order_does_not_grant_cross_rule_merge():
    snapshot = make_snapshot(
        [
            {"host": "x.test", "ports": [443], "networks": ["10.0.0.0/8"]},
            {"host": "*.test", "ports": [443], "networks": ["172.16.0.0/12"]},
        ]
    )
    # 10.x is covered by rule 1, 172.16 by rule 2, but no single rule covers both.
    decision = snapshot.admit("x.test", 443, ["10.0.0.1", "172.16.0.1"])
    assert not decision.allowed


def test_ipv6_addresses_are_not_admitted():
    snapshot = make_snapshot([{"host": "x.test", "ports": [443], "networks": ["0.0.0.0/0"]}])
    decision = snapshot.admit("x.test", 443, ["2001:db8::1"])
    assert not decision.allowed
    assert decision.reason == "non_ipv4_address"
