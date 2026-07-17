"""One-click TEST authorization — Scope.for_testing (the frictionless dev/test path)."""

from __future__ import annotations

import pytest

from attack_engine.schemas.scope import (
    TEST_AUTHORIZATION_SIGNATURE,
    Scope,
)


def test_for_testing_builds_a_signed_autonomous_scope() -> None:
    scope = Scope.for_testing(["10.5.0.12"])
    assert scope.is_signed()                       # runs without a real signature
    assert scope.is_test_authorization             # ...but flagged as test-only
    assert scope.signature == TEST_AUTHORIZATION_SIGNATURE
    assert scope.roe.autonomy_tier == 2
    assert scope.roe.read_only is False            # can actually act, not just scan
    assert "establish_foothold" in scope.roe.authorized_techniques


def test_for_testing_classifies_ips_cidrs_and_hosts() -> None:
    scope = Scope.for_testing(["10.5.0.12", "192.168.0.0/24", "testphp.vulnweb.com"])
    assert "10.5.0.12/32" in scope.allowed_cidrs
    assert "192.168.0.0/24" in scope.allowed_cidrs
    assert "testphp.vulnweb.com" in scope.allowed_hosts


def test_for_testing_strips_url_scheme_and_path() -> None:
    scope = Scope.for_testing(["https://testphp.vulnweb.com/login.php?x=1"])
    assert scope.allowed_hosts == ("testphp.vulnweb.com",)


def test_for_testing_auto_expires() -> None:
    scope = Scope.for_testing(["10.5.0.12"], ttl_hours=8)
    assert scope.expires_at is not None
    assert not scope.is_expired()                  # fresh test auth is valid now


def test_for_testing_requires_a_target() -> None:
    with pytest.raises(ValueError, match="at least one target"):
        Scope.for_testing([])


def test_for_testing_custom_tier_and_techniques() -> None:
    scope = Scope.for_testing(
        ["10.5.0.12"], autonomy_tier=1, authorized_techniques=frozenset({"T1190"})
    )
    assert scope.roe.autonomy_tier == 1
    assert scope.roe.authorized_techniques == frozenset({"T1190"})


def test_real_scope_is_not_a_test_authorization() -> None:
    scope = Scope(
        engagement_id="engagement-real", allowed_cidrs=("10.0.0.0/24",),
        authorized_by="lead@corp", signature="a-real-signature",
    )
    assert scope.is_signed() and not scope.is_test_authorization
