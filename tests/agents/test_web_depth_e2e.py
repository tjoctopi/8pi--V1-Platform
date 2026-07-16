"""Phase D capstone — the whole web-depth flow wired together, offline.

crawl output → WebObserver beliefs → WebGraduator (with payload synthesis) →
oracle-ready Findings → WebChainer composes the escalation path → an oracle
confirms the entry rung → the chain lights up. No Docker/network; the real
components, fakes at the I/O edges.
"""

from __future__ import annotations

from attack_engine.agents.actions import ActionOutcome, ProposedAction
from attack_engine.agents.payload_synth import PayloadSynthesizer
from attack_engine.agents.reasoning import LoopContext
from attack_engine.agents.web_chain import WebChainer
from attack_engine.agents.web_specialist import WebGraduator, WebObserver
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.findings import FindingState
from attack_engine.schemas.tools import ToolResult


def _katana(wm: WorldModel) -> None:
    parsed = {"endpoints": [
        {"url": "http://10.5.0.20/item?id=1", "path": "/item", "params": ["id"]},
        {"url": "http://10.5.0.20/dl?file=a", "path": "/dl", "params": ["file"]},
        {"url": "http://10.5.0.20/fetch?url=x", "path": "/fetch", "params": ["url"]},
    ]}
    result = ToolResult(tool="katana", target="10.5.0.20", raw=b"", parsed=parsed,
                        exit_code=0, audit_id="aud", engagement_id=wm.engagement_id)
    WebObserver().observe(
        ProposedAction(tool="katana", target="10.5.0.20", rationale="crawl"),
        ActionOutcome(ok=True, summary="ok", raw=result),
        LoopContext(wm, objective="web", history=(), step=0, budget=None),
    )


def test_phase_d_crawl_to_chained_proof() -> None:
    store = KnowledgeStore("engagement-range")
    wm = WorldModel("engagement-range", store=store)

    # 1. Crawl → beliefs (per-param class candidates).
    _katana(wm)
    kinds = {h.kind for h in wm.open_hypotheses()}
    assert {"sqli", "lfi", "ssrf", "open-redirect"} <= kinds

    # 2. Graduate the oracle-ready ones into Findings, enriched with payloads.
    graduated = WebGraduator(store, synthesizer=PayloadSynthesizer()).graduate(wm)
    by_type = {f.type: f for f in graduated}
    assert "sqli-boolean-blind" in by_type and "lfi" in by_type and "ssrf" in by_type
    # payload synthesis populated the oracle metadata
    assert by_type["lfi"].metadata["payloads"]
    assert by_type["sqli-boolean-blind"].metadata["true_payload"]
    # every graduated finding routes to a real confirmation oracle
    from attack_engine.verify.oracles import default_oracle_registry
    reg = default_oracle_registry()
    assert all(reg.for_finding(f) is not None for f in graduated)

    # 3. Compose escalation chains from the strong entry beliefs.
    chains = WebChainer().compose(wm, min_confidence=0.4)
    objectives = {c.objective for c in chains}
    assert any("ssrf" in o and "foothold" in o for o in objectives)
    ssrf_chain = next(c for c in chains if c.steps[0].kind == "ssrf")
    assert ssrf_chain.confirmed_depth == 0  # planned, nothing proven yet

    # 4. A deterministic oracle confirms the SSRF entry → the chain lights up.
    ssrf_finding = by_type["ssrf"]
    store.promote_finding(ssrf_finding.id, FindingState.VERIFIED, verified_by="ssrf_oob_oracle_v1")
    store.promote_finding(ssrf_finding.id, FindingState.CONFIRMED, verified_by="ssrf_oob_oracle_v1")
    [refreshed] = [c for c in WebChainer().refresh(wm) if c.id == ssrf_chain.id]
    assert refreshed.steps[0].confirmed
    assert refreshed.confirmed_depth == 1
    assert not refreshed.is_realised  # downstream rungs still to prove
