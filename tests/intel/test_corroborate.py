"""Observation corroboration (false-positive gate) tests."""

from __future__ import annotations

from attack_engine.intel.corroborate import (
    CONFIRMED,
    REPORTED,
    UNCONFIRMED,
    corroborate,
    tech_vocabulary,
)


def test_uncorroborated_critical_is_unconfirmed() -> None:
    # nginx fingerprint, but the template claims VMware ESXi — no overlap.
    vocab = tech_vocabulary("nginx https")
    confidence, reason = corroborate(
        name="VMware ESXi SLP - Heap Overflow DoS",
        template_id="vmware-esxi-slp-heap-overflow",
        severity="critical", tech_tokens=vocab,
    )
    assert confidence == UNCONFIRMED
    assert "no service/tech fingerprint" in reason


def test_corroborated_critical_when_fingerprint_matches() -> None:
    vocab = tech_vocabulary("Apache WordPress php")
    confidence, reason = corroborate(
        name="WordPress core RCE", template_id="wordpress-core-rce",
        severity="critical", tech_tokens=vocab,
    )
    assert confidence == CONFIRMED
    assert "wordpress" in reason


def test_informational_needs_no_corroboration() -> None:
    confidence, _ = corroborate(
        name="WAF Detection", template_id="waf-detect",
        severity="info", tech_tokens=set(),
    )
    assert confidence == REPORTED


def test_generic_tokens_do_not_self_corroborate() -> None:
    # A "default-login-panel" critical must not corroborate off the word "login"
    # appearing in an asset's fingerprint — generic tokens carry no identity.
    vocab = tech_vocabulary("login page server http")
    confidence, _ = corroborate(
        name="Default Login Panel", template_id="default-login-panel",
        severity="high", tech_tokens=vocab,
    )
    assert confidence == UNCONFIRMED
