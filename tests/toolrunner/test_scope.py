"""Scope enforcement tests — the boundary that must exist before any offense."""

from __future__ import annotations

import ipaddress

import pytest

from attack_engine.errors import ScopeViolationError
from attack_engine.schemas import Scope
from attack_engine.schemas.common import utcnow
from attack_engine.toolrunner.scope import ScopeEnforcer


class TestInScope:
    def test_ip_inside_allowed_cidr(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.4.12")
        assert enf.allows("10.0.4.1")
        assert enf.allows("10.0.4.254")
        assert enf.allows("192.168.56.101")

    def test_network_and_broadcast_addresses(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.4.0")
        assert enf.allows("10.0.4.255")

    def test_allowed_host_exact_match(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("juice.local")
        assert enf.allows("JUICE.LOCAL")  # case-insensitive
        assert enf.allows("juice.local.")  # trailing dot tolerated


class TestOutOfScope:
    def test_ip_outside_all_cidrs(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert not enf.allows("10.0.5.1")  # adjacent /24
        assert not enf.allows("8.8.8.8")
        assert not enf.allows("172.16.0.1")

    def test_unlisted_host(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert not enf.allows("evil.example.com")

    def test_check_raises_with_target_and_reason(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        with pytest.raises(ScopeViolationError) as ei:
            enf.check("8.8.8.8")
        assert ei.value.target == "8.8.8.8"
        assert "allowlist" in ei.value.reason

    def test_empty_target_denied(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert not enf.allows("")
        assert not enf.allows("   ")


class TestExpiry:
    def test_expired_scope_refuses_even_in_scope_target(self, scope: Scope) -> None:
        expired = scope.model_copy(
            update={"expires_at": utcnow().replace(year=2000)}
        )
        enf = ScopeEnforcer(expired)
        with pytest.raises(ScopeViolationError) as ei:
            enf.check("10.0.4.12")
        assert "expired" in ei.value.reason


class TestResolver:
    def test_hostname_in_scope_when_all_resolved_ips_allowed(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope, resolver=lambda _h: ["10.0.4.50"])
        assert enf.allows("dynamic.host")

    def test_hostname_out_of_scope_when_any_resolved_ip_denied(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope, resolver=lambda _h: ["10.0.4.50", "8.8.8.8"])
        assert not enf.allows("dynamic.host")

    def test_unresolvable_host_fails_closed(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope, resolver=lambda _h: [])
        assert not enf.allows("nxdomain.host")


class TestRadixTrieCorrectness:
    """Property-style checks: the trie must agree with stdlib ipaddress."""

    def test_matches_ipaddress_over_sample(self) -> None:
        scope = Scope(
            engagement_id="eng-trie",
            allowed_cidrs=("10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32"),
            allowed_hosts=(),
        )
        enf = ScopeEnforcer(scope)
        nets = [ipaddress.ip_network(c) for c in scope.allowed_cidrs]
        samples = [
            "10.255.255.255",
            "10.0.0.1",
            "11.0.0.1",
            "192.168.1.128",
            "192.168.2.1",
            "127.0.0.1",
            "127.0.0.2",
            "0.0.0.0",
        ]
        for s in samples:
            ip = ipaddress.ip_address(s)
            expected = any(ip in n for n in nets)
            assert enf.allows(s) is expected, s

    def test_ipv6_cidr(self) -> None:
        scope = Scope(
            engagement_id="eng-v6",
            allowed_cidrs=("2001:db8::/32",),
            allowed_hosts=(),
        )
        enf = ScopeEnforcer(scope)
        assert enf.allows("2001:db8::1")
        assert enf.allows("2001:db8:ffff::1")
        assert not enf.allows("2001:db9::1")
        assert not enf.allows("::1")

    def test_catch_all_cidr(self) -> None:
        scope = Scope(engagement_id="eng-all", allowed_cidrs=("0.0.0.0/0",))
        enf = ScopeEnforcer(scope)
        assert enf.allows("1.2.3.4")
        assert enf.allows("222.222.222.222")

    def test_stats_report_counts(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        stats = enf.stats()
        assert stats["cidrs_v4"] == 2
        assert stats["hosts"] == 2


class TestCidrSweep:
    """A range sweep (e.g. `nmap 10.5.0.0/24`) is in scope only when the whole
    range is contained in an allow-listed CIDR — deny-by-default preserved."""

    def test_cidr_equal_to_allowed_is_in_scope(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.4.0/24") is True

    def test_sub_cidr_of_allowed_is_in_scope(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.4.0/26") is True
        assert enf.allows("10.0.4.128/25") is True

    def test_single_host_as_slash32_in_scope(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.4.10/32") is True

    def test_supernet_of_allowed_is_refused(self, scope: Scope) -> None:
        # /16 is broader than the allowed /24 → must NOT be allowed.
        enf = ScopeEnforcer(scope)
        assert enf.allows("10.0.0.0/16") is False

    def test_out_of_scope_cidr_refused(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        assert enf.allows("172.16.0.0/24") is False

    def test_check_passes_for_in_scope_sweep(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        enf.check("10.0.4.0/24")  # must not raise

    def test_check_raises_for_broad_sweep(self, scope: Scope) -> None:
        enf = ScopeEnforcer(scope)
        with pytest.raises(ScopeViolationError):
            enf.check("10.0.0.0/8")
