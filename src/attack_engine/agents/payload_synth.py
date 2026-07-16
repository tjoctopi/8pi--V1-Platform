"""Payload synthesis (Phase D) — context-aware proof payloads, LLM-proposed.

A static wordlist tries the same ``../../etc/passwd`` on every target; an operator
tailors the payload to the *context* — the OS, the DB dialect, the encoding the
edge strips. This synthesizer asks the model for context-aware **proof** payloads
(benign, capability-proving — never destructive), then **deterministic code
decides** which are safe to use and hands them to the oracle to prove (rule #1:
the model proposes, code/oracle disposes). A deterministic library is both the
offline fallback (no gateway) and the safety net if the model misbehaves.

Only classes whose oracle *consumes* a payload are enriched: LFI (traversal
variants) and boolean-blind SQLi (dialect-aware true/false pair). SSTI, reflected
XSS, SSRF and open-redirect are proven by fixed markers/tokens whose integrity the
proof depends on, so they are never overridden here.
"""

from __future__ import annotations

from pydantic import Field

from ..gateway.budget import TokenBudget
from ..gateway.router import ModelGateway
from ..gateway.types import ChatMessage
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from ..schemas.common import StrictModel
from ..schemas.findings import Finding

_log = get_logger("agent.payload_synth")

#: Characters we never allow through in a synthesized payload — the same shell
#: metacharacters the Tool Runner rejects, plus NUL. The model *proposes*; this
#: list is code *disposing* of anything unsafe before it can reach a wrapper.
_UNSAFE = set(";|&`$\n\r\x00")

_MAX_PAYLOADS = 12
_MAX_LEN = 256

#: Deterministic fallback / safety-net libraries per class.
_LFI_LINUX = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
)
_LFI_WINDOWS = (
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
)


class SynthesizedPayloads(StrictModel):
    """Structured payload proposal returned by the model (or the fallback)."""

    rationale: str = ""
    payloads: tuple[str, ...] = Field(default_factory=tuple)  # LFI/traversal variants
    base_value: str | None = None  # SQLi seed value (e.g. "1")
    true_payload: str | None = None  # SQLi always-true condition
    false_payload: str | None = None  # SQLi always-false condition


_SYSTEM_PROMPT = (
    "You are the Payload Synthesizer for an authorized red-team engagement. Given "
    "a vulnerability class and endpoint context, propose CONTEXT-AWARE, benign "
    "PROOF payloads — payloads that prove the capability (read a known file, "
    "differentiate a true vs false condition) without altering or exfiltrating "
    "data. Never propose destructive or data-stealing payloads. Tailor to the OS / "
    "DB dialect implied by the tech context. Return only the structured payloads."
)


def _finding_class(finding_type: str) -> str | None:
    """Which synthesizable class a finding is, or None if it takes fixed proofs."""

    if finding_type.startswith(("lfi", "path-traversal", "file-read")):
        return "lfi"
    if finding_type.startswith("sqli"):
        return "sqli"
    return None


class PayloadSynthesizer:
    """Produces validated, context-aware payloads for a finding's oracle."""

    def __init__(
        self,
        gateway: ModelGateway | None = None,
        *,
        tier: ModelTier = ModelTier.FRONTIER,
        engagement_id: str | None = None,
        actor: str = "payload-synth",
    ) -> None:
        self._gateway = gateway
        self._tier = tier
        self._engagement_id = engagement_id
        self._actor = actor

    def synthesize(
        self,
        cls: str,
        *,
        path: str = "/",
        param: str | None = None,
        tech: str = "",
        budget: TokenBudget | None = None,
    ) -> SynthesizedPayloads:
        """Context-aware payloads for ``cls``; model-driven with a safe fallback."""

        proposal = self._fallback(cls, tech)
        if self._gateway is not None:
            try:
                proposal = self._ask_model(cls, path, param, tech, budget)
            except Exception as exc:  # never let payload synthesis break a run
                _log.warning("payload synth: model failed, using fallback", error=str(exc))
        return self._sanitize(cls, proposal, tech)

    def enrich(
        self, finding: Finding, *, tech: str = "", budget: TokenBudget | None = None
    ) -> Finding:
        """Return ``finding`` with oracle-consumable payloads merged into metadata.

        A class the oracle proves with a fixed marker is returned unchanged.
        """

        cls = _finding_class(finding.type)
        if cls is None:
            return finding
        md = finding.metadata
        s = self.synthesize(
            cls, path=str(md.get("path", "/")), param=md.get("param"), tech=tech, budget=budget
        )
        extra: dict[str, object] = {}
        if cls == "lfi" and s.payloads:
            extra["payloads"] = list(s.payloads)
        if cls == "sqli":
            if s.base_value is not None:
                extra["base_value"] = s.base_value
            if s.true_payload:
                extra["true_payload"] = s.true_payload
            if s.false_payload:
                extra["false_payload"] = s.false_payload
        if not extra:
            return finding
        return finding.model_copy(update={"metadata": {**md, **extra}})

    # --- internals ------------------------------------------------------------

    def _ask_model(
        self,
        cls: str,
        path: str,
        param: str | None,
        tech: str,
        budget: TokenBudget | None,
    ) -> SynthesizedPayloads:
        state = (
            f"CLASS: {cls}\nPATH: {path}\nPARAM: {param or '(path-based)'}\n"
            f"TECH CONTEXT: {tech or 'unknown'}\n\n"
            "Propose context-aware proof payloads for this class."
        )
        return self._gateway.respond_json(  # type: ignore[union-attr]
            [ChatMessage.system(_SYSTEM_PROMPT), ChatMessage.user(state)],
            SynthesizedPayloads,
            tier=self._tier,
            engagement_id=self._engagement_id,
            actor=self._actor,
            budget=budget,
        )

    @staticmethod
    def _fallback(cls: str, tech: str) -> SynthesizedPayloads:
        if cls == "lfi":
            windows = "win" in tech.lower()
            payloads = _LFI_WINDOWS + _LFI_LINUX if windows else _LFI_LINUX + _LFI_WINDOWS
            return SynthesizedPayloads(rationale="library traversal set", payloads=payloads)
        if cls == "sqli":
            return SynthesizedPayloads(
                rationale="library boolean pair",
                base_value="1",
                true_payload="1' AND '1'='1",
                false_payload="1' AND '1'='2",
            )
        return SynthesizedPayloads()

    def _sanitize(self, cls: str, s: SynthesizedPayloads, tech: str) -> SynthesizedPayloads:
        """Deterministic gate: drop unsafe/oversized payloads; guarantee a usable set."""

        safe = [
            p for p in s.payloads
            if p and len(p) <= _MAX_LEN and not (_UNSAFE & set(p))
        ]
        safe = list(dict.fromkeys(safe))[:_MAX_PAYLOADS]
        def _ok(v: str | None) -> bool:
            return v is None or not (_UNSAFE & set(v))

        base = s.base_value if _ok(s.base_value) else None
        true_p = s.true_payload if (s.true_payload and _ok(s.true_payload)) else None
        false_p = s.false_payload if (s.false_payload and _ok(s.false_payload)) else None

        # If the model left the needed field empty/unsafe, fall back deterministically.
        fb = self._fallback(cls, tech)
        if cls == "lfi" and not safe:
            safe = list(fb.payloads)
        if cls == "sqli" and not (true_p and false_p):
            base, true_p, false_p = fb.base_value, fb.true_payload, fb.false_payload
        return SynthesizedPayloads(
            rationale=s.rationale, payloads=tuple(safe),
            base_value=base, true_payload=true_p, false_payload=false_p,
        )
