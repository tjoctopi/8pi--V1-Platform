"""Payload synthesis — model proposes, deterministic gate disposes, oracle proves.

Covers the offline fallback (no gateway), the model path (scripted structured
output), the safety gate (unsafe payloads dropped), and enrichment of a finding's
oracle metadata.
"""

from __future__ import annotations

from attack_engine.agents.payload_synth import PayloadSynthesizer, SynthesizedPayloads
from attack_engine.config import Settings
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.schemas.findings import Finding


def _gateway(responder) -> ModelGateway:
    return ModelGateway(settings=Settings(model_mock=True), provider=MockProvider(responder=responder))


# --- deterministic fallback (no gateway) ---------------------------------------


def test_fallback_lfi_prefers_os_from_tech() -> None:
    syn = PayloadSynthesizer()
    linux = syn.synthesize("lfi", tech="nginx/Ubuntu")
    win = syn.synthesize("lfi", tech="IIS/Windows Server")
    assert "etc/passwd" in linux.payloads[0]
    assert "win.ini" in win.payloads[0]


def test_fallback_sqli_gives_true_false_pair() -> None:
    s = PayloadSynthesizer().synthesize("sqli")
    assert s.true_payload and s.false_payload and s.true_payload != s.false_payload


# --- model path + safety gate --------------------------------------------------


def test_model_payloads_used_when_safe() -> None:
    def responder(_m) -> str:
        return '{"payloads": ["../../../../etc/passwd", "..%2f..%2fetc%2fpasswd"], "rationale": "ctx"}'

    s = PayloadSynthesizer(_gateway(responder)).synthesize("lfi", param="file")
    assert list(s.payloads) == ["../../../../etc/passwd", "..%2f..%2fetc%2fpasswd"]


def test_unsafe_payloads_are_dropped_by_the_gate() -> None:
    # The model proposes a command-injection payload; the deterministic gate must
    # drop it (shell metachars) and fall back rather than pass it through.
    def responder(_m) -> str:
        return '{"payloads": ["; cat /etc/shadow", "`id`"], "rationale": "evil"}'

    s = PayloadSynthesizer(_gateway(responder)).synthesize("lfi")
    assert all(";" not in p and "`" not in p for p in s.payloads)
    assert s.payloads  # non-empty: fell back to the safe library


def test_synth_never_raises_on_model_error() -> None:
    def responder(_m) -> str:
        return "not json at all"

    # respond_json fails → synthesize swallows and returns the fallback.
    s = PayloadSynthesizer(_gateway(responder)).synthesize("sqli")
    assert s.true_payload and s.false_payload


# --- enrichment ----------------------------------------------------------------


def test_enrich_lfi_finding_adds_payloads() -> None:
    f = Finding(engagement_id="e", asset="a", type="lfi", metadata={"param": "file", "path": "/dl"})
    out = PayloadSynthesizer().enrich(f)
    assert out.metadata["payloads"]
    assert "etc/passwd" in out.metadata["payloads"][0] or "win.ini" in out.metadata["payloads"][0]


def test_enrich_sqli_finding_adds_boolean_pair() -> None:
    f = Finding(engagement_id="e", asset="a", type="sqli-boolean-blind", metadata={"param": "id"})
    out = PayloadSynthesizer().enrich(f)
    assert out.metadata["true_payload"] and out.metadata["false_payload"]


def test_enrich_leaves_fixed_proof_classes_untouched() -> None:
    # SSTI/XSS/SSRF are proven by fixed markers — enrich must not alter them.
    f = Finding(engagement_id="e", asset="a", type="ssti", metadata={"param": "name"})
    assert PayloadSynthesizer().enrich(f) is f


def test_sanitize_direct() -> None:
    raw = SynthesizedPayloads(payloads=("ok/path", "bad;rm", "x" * 500), true_payload="a`b")
    gated = PayloadSynthesizer()._sanitize("lfi", raw, tech="")
    assert "ok/path" in gated.payloads
    assert all(";" not in p and len(p) <= 256 for p in gated.payloads)
