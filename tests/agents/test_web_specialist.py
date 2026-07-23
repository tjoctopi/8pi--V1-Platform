"""Web specialist on the loop — the WebObserver (web output → oracle-ready
hypotheses), the WebGraduator (hypotheses → PROPOSED Findings an oracle can
confirm), and a full run through the real Tool Runner with a fake sandbox.

Like the recon suite, the end-to-end test drives a scripted model plan through
the real boundary so katana output is genuinely parsed and folded into beliefs —
no Docker, no network, but the real wiring.
"""

from __future__ import annotations

import json

import pytest

from attack_engine.agents.actions import ActionOutcome, ProposedAction
from attack_engine.agents.context import AgentContext
from attack_engine.agents.reasoning import LoopContext
from attack_engine.agents.web_specialist import (
    WebGraduator,
    WebObserver,
    _param_classes,
    build_web_loop,
)
from attack_engine.config import Settings
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.findings import FindingState
from attack_engine.schemas.tools import ToolResult
from attack_engine.verify.oracles import default_oracle_registry


def _tool_result(tool: str, target: str, parsed: dict) -> ToolResult:
    return ToolResult(
        tool=tool, target=target, raw=b"", parsed=parsed, exit_code=0,
        audit_id="aud-1", engagement_id="eng-1",
    )


def _loop_ctx(wm: WorldModel) -> LoopContext:
    return LoopContext(wm, objective="web", history=(), step=0, budget=None)


def _outcome(result: ToolResult) -> ActionOutcome:
    return ActionOutcome(ok=True, summary="ok", raw=result)


def _observe(wm: WorldModel, tool: str, target: str, parsed: dict) -> None:
    WebObserver().observe(
        ProposedAction(tool=tool, target=target, rationale="x"),
        _outcome(_tool_result(tool, target, parsed)),
        _loop_ctx(wm),
    )


# --- param-class inference ------------------------------------------------------


def test_param_classes_infers_specific_and_universal() -> None:
    assert "sqli" in _param_classes("anything")  # SQLi considered for every param
    assert "lfi" in _param_classes("file")
    assert "ssrf" in _param_classes("redirect_url")
    assert "open-redirect" in _param_classes("redirect_url")
    assert "idor" in _param_classes("user_id")
    assert "xss" in _param_classes("search")


def test_param_classes_short_hint_no_false_positive() -> None:
    # 'id' (short hint) must not fire IDOR on 'video'.
    assert "idor" not in _param_classes("video")
    assert "idor" in _param_classes("id")


# --- WebObserver: web output -> beliefs -----------------------------------------


def test_observer_katana_endpoints_become_candidates() -> None:
    wm = WorldModel("eng-1")
    _observe(
        wm, "katana", "10.0.4.12",
        {"endpoints": [
            {"url": "http://10.0.4.12/item?file=x", "path": "/item", "params": ["file"]},
        ]},
    )
    by_kind = {h.kind for h in wm.open_hypotheses()}
    assert "lfi" in by_kind  # 'file' smells like LFI
    assert "sqli" in by_kind  # and every param is a SQLi candidate


def test_observer_post_form_becomes_cmdi_candidate_with_request_context() -> None:
    # A crawled POST form (katana -fx -aff): the injectable field becomes a cmdi
    # candidate carrying the request context (method + companion fields + query)
    # the oracle needs to submit the form — the fix that lets Full Attack reach a
    # command-execution foothold behind a POST form.
    wm = WorldModel("eng-1")
    _observe(
        wm, "katana", "10.5.0.12",
        {"endpoints": [{
            "url": "http://10.5.0.12/mutillidae/index.php?page=dns-lookup.php",
            "path": "/mutillidae/index.php", "params": ["page"], "method": "POST",
            "form": {"target_host": "katana", "dns-lookup-php-submit-button": "Lookup DNS"},
        }]},
    )
    # target_host smells like command injection; its candidate carries the
    # companion field (the submit button) + endpoint query as fixed context.
    cmdi = next(h for h in wm.open_hypotheses()
                if h.kind == "cmdi" and h.subject.endswith("?target_host"))
    ctx = cmdi.context
    assert ctx["method"] == "POST"
    assert ctx["params"] == {"page": "dns-lookup.php"}  # the endpoint query rides along
    assert ctx["data"] == {"dns-lookup-php-submit-button": "Lookup DNS"}  # companion field


def test_graduator_carries_post_form_context_into_finding() -> None:
    # The POST context survives graduation, so the command-injection oracle
    # submits the form (method=POST → inject into `data`) rather than a GET query.
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    _observe(
        wm, "katana", "10.5.0.12",
        {"endpoints": [{
            "url": "http://10.5.0.12/mutillidae/index.php?page=dns-lookup.php",
            "path": "/mutillidae/index.php", "params": ["page"], "method": "POST",
            "form": {"target_host": "katana", "dns-lookup-php-submit-button": "Lookup DNS"},
        }]},
    )
    # Bump the cmdi lead over the graduation floor (a crawl candidate starts low).
    cmdi = next(h for h in wm.open_hypotheses() if h.kind == "cmdi")
    from attack_engine.schemas.beliefs import Observation
    wm.observe(cmdi.id, Observation(source="nuclei", probability=0.8))

    graduated = WebGraduator(store).graduate(wm, min_confidence=0.5)
    f = next(g for g in graduated if g.type == "command-injection")
    assert f.metadata["param"] == "target_host"
    assert f.metadata["method"] == "POST"
    assert f.metadata["params"] == {"page": "dns-lookup.php"}
    assert f.metadata["data"] == {"dns-lookup-php-submit-button": "Lookup DNS"}
    # ...and it routes to the command-injection oracle.
    assert default_oracle_registry().for_finding(f) is not None


def test_observer_dalfox_reflected_is_strong_xss() -> None:
    wm = WorldModel("eng-1")
    _observe(
        wm, "dalfox", "http://10.0.4.12/s?q=1",
        {"findings": [{"param": "q", "inject_type": "inHTML", "method": "GET"}]},
    )
    xss = [h for h in wm.open_hypotheses() if h.kind == "xss"]
    assert len(xss) == 1
    assert xss[0].confidence > 0.6  # a real reflection is high-confidence


def test_observer_sqlmap_injectable_is_strong_sqli() -> None:
    wm = WorldModel("eng-1")
    _observe(
        wm, "sqlmap", "http://10.0.4.12/item?id=1",
        {"injectable": True, "parameter": "id", "technique": "boolean-based blind"},
    )
    sqli = [h for h in wm.open_hypotheses() if h.kind == "sqli"]
    assert len(sqli) == 1 and sqli[0].confidence > 0.7


def test_observer_sqlmap_not_injectable_adds_nothing() -> None:
    wm = WorldModel("eng-1")
    _observe(wm, "sqlmap", "http://10.0.4.12/x?id=1",
             {"injectable": False, "parameter": None, "technique": None})
    assert wm.hypotheses() == []


def test_observer_nuclei_classifies_template() -> None:
    wm = WorldModel("eng-1")
    _observe(
        wm, "nuclei", "10.0.4.12",
        {"results": [
            {"template_id": "sqli-detection", "name": "SQLi", "severity": "high",
             "matched_at": "http://10.0.4.12/item?id=1", "type": "http"},
            {"template_id": "CVE-2014-6271", "name": "Shellshock",
             "severity": "critical", "matched_at": "http://10.0.4.12/cgi-bin", "type": "http"},
        ]},
    )
    by_kind = {h.kind for h in wm.open_hypotheses()}
    assert "sqli" in by_kind
    assert "cve" in by_kind  # a CVE template stays a (non-graduating) CVE lead


def test_observer_dedupes_repeated_signal() -> None:
    wm = WorldModel("eng-1")
    parsed = {"findings": [{"param": "q", "inject_type": "inHTML", "method": "GET"}]}
    _observe(wm, "dalfox", "http://10.0.4.12/s?q=1", parsed)
    _observe(wm, "dalfox", "http://10.0.4.12/s?q=1", parsed)
    xss = [h for h in wm.hypotheses() if h.kind == "xss"]
    assert len(xss) == 1  # one belief
    assert len(xss[0].observations) == 2  # reinforced by the repeat


def test_observer_ignores_failed_outcome() -> None:
    wm = WorldModel("eng-1")
    WebObserver().observe(
        ProposedAction(tool="katana", target="t", rationale="x"),
        ActionOutcome(ok=False, summary="degraded", raw=None),
        _loop_ctx(wm),
    )
    assert wm.hypotheses() == []


# --- WebGraduator: hypotheses -> oracle-ready Findings --------------------------


def test_graduator_promotes_oracle_ready_and_skips_the_rest() -> None:
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    # A strong, oracle-backed SQLi lead...
    _observe(wm, "sqlmap", "http://10.0.4.12:8080/item?id=1",
             {"injectable": True, "parameter": "id", "technique": "boolean-based blind"})
    # ...and an IDOR lead, which has no oracle yet (must NOT graduate).
    wm.add_hypothesis(subject="http://10.0.4.12/acct?account=7", kind="idor",
                      title="idor", prior=0.9, observations=())

    graduated = WebGraduator(store).graduate(wm, min_confidence=0.5)

    assert len(graduated) == 1
    f = graduated[0]
    assert f.type == "sqli-boolean-blind" and f.state is FindingState.PROPOSED
    assert f.asset == "10.0.4.12"
    assert f.metadata["param"] == "id" and f.metadata["port"] == 8080
    assert f.metadata["path"] == "/item"
    # The graduated finding is routable to a real confirmation oracle.
    assert default_oracle_registry().for_finding(f) is not None
    # The hypothesis is now linked to its finding (no longer an open lead).
    assert not any(h.kind == "sqli" for h in wm.open_hypotheses())


def test_graduator_respects_confidence_floor() -> None:
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    # A bare crawl candidate (prior only, low confidence) stays a lead.
    _observe(wm, "katana", "10.0.4.12",
             {"endpoints": [{"url": "http://10.0.4.12/x?id=1", "path": "/x", "params": ["id"]}]})
    graduated = WebGraduator(store).graduate(wm, min_confidence=0.8)
    assert graduated == []
    assert store.findings() == []


def test_graduator_skips_param_classes_without_a_param() -> None:
    # An SSRF class needs an injection param; a param-less subject can't graduate.
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    wm.add_hypothesis(subject="http://10.0.4.12/fetch", kind="ssrf", title="ssrf",
                      prior=0.9, observations=())
    assert WebGraduator(store).graduate(wm, min_confidence=0.5) == []


# --- factory / guardrails -------------------------------------------------------


def test_build_web_loop_requires_gateway(ctx: AgentContext) -> None:
    ctx.gateway = None
    with pytest.raises(ValueError, match="model gateway"):
        build_web_loop(ctx)


# --- end-to-end through the real Tool Runner ------------------------------------


def test_web_loop_crawls_and_graduates_end_to_end(ctx: AgentContext, fake_sandbox) -> None:
    from attack_engine.toolrunner.sandbox import SandboxResult

    katana_jsonl = "\n".join(
        json.dumps({"endpoint": url})
        for url in ("http://10.0.4.12/item?id=1", "http://10.0.4.12/doc?file=a")
    ).encode()
    fake_sandbox.set_response("katana", SandboxResult(0, katana_jsonl, b"", 0.05, "fake"))

    calls = {"n": 0}

    def responder(_messages) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return (
                '{"actions": [{"tool": "katana", "target": "10.0.4.12", '
                '"rationale": "crawl for params", "expected_value": 0.9}]}'
            )
        return '{"actions": [{"tool": "finish", "rationale": "done", "expected_value": 1.0}]}'

    ctx.gateway = ModelGateway(
        settings=Settings(model_mock=True), provider=MockProvider(responder=responder)
    )
    wm = WorldModel(ctx.engagement_id, store=ctx.store)
    loop = build_web_loop(ctx)
    result = loop.run(wm, "find and prove a web vulnerability")

    # The katana output flowed through the real Tool Runner, became beliefs, and
    # the oracle-ready ones AUTO-GRADUATED into PROPOSED findings in the one loop
    # (build_web_loop now graduates each step — the autonomous recon→proof seam).
    assert result.iterations >= 1
    from attack_engine.schemas.findings import FindingState

    proposed = {f.type for f in ctx.store.findings(FindingState.PROPOSED)}
    assert "lfi" in proposed  # the 'file' param
    assert "sqli-boolean-blind" in proposed  # every param is a SQLi candidate
    # Graduated beliefs are linked and no longer dangle as open leads.
    assert "lfi" not in {h.kind for h in wm.open_hypotheses()}
    # Every graduated finding is oracle-ready (a registered oracle can confirm it).
    for f in ctx.store.findings(FindingState.PROPOSED):
        assert default_oracle_registry().for_finding(f) is not None
