"""RoE tool allowlist decisions (Slice 2) — the console 'Allowed Tools' picker,
enforced at the Tool Runner boundary."""

from __future__ import annotations

from attack_engine.governance.roe import RoEEvaluator
from attack_engine.schemas.scope import RulesOfEngagement, Scope


def _eval(**roe_kw: object) -> RoEEvaluator:
    scope = Scope(
        engagement_id="eng-roe-0001",
        allowed_cidrs=("10.0.0.0/24",),
        roe=RulesOfEngagement(**roe_kw),
        authorized_by="t@8pi.ai",
        signature="sig",
    )
    return RoEEvaluator(scope)


def test_empty_allowlist_means_no_restriction() -> None:
    ev = _eval()  # allowed_tools empty
    assert ev.is_tool_allowed("nmap")
    assert ev.is_tool_allowed("nuclei")
    assert ev.is_tool_allowed("anything")


def test_non_empty_allowlist_is_exclusive() -> None:
    ev = _eval(allowed_tools=frozenset({"nmap", "httpx"}))
    assert ev.is_tool_allowed("nmap")
    assert ev.is_tool_allowed("httpx")
    assert not ev.is_tool_allowed("nuclei")


def test_denylist_and_allowlist_are_independent() -> None:
    ev = _eval(allowed_tools=frozenset({"nmap"}), forbidden_tools=frozenset({"nmap"}))
    # allowlist admits nmap, but the denylist is checked separately and wins.
    assert ev.is_tool_allowed("nmap")
    assert ev.is_tool_forbidden("nmap")
