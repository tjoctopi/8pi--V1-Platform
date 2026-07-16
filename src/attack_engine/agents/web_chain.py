"""Web chaining engine (Phase D) — compose weak links into a compromise path.

An elite operator does not stop at a single finding; they ask "what does this
*unlock*?" and chain low-severity into high (agent-fleet habit #3). This module
turns a strong entry belief — a proven or high-confidence web vulnerability —
into an :class:`~attack_engine.schemas.chains.AttackChain`: the classic
escalation path from that class to a real foothold, tracked in the world model so
the objective controller can pursue it and watch it light up rung by rung.

Proposal-space only (rule #1): the chain is a *plan*. Each rung still graduates to
a Finding and is proven by its own deterministic oracle; :meth:`WebChainer.refresh`
marks a rung ``confirmed`` only when a matching CONFIRMED finding exists. The
chain is "realised" only when every rung it depends on is independently proven.
"""

from __future__ import annotations

from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.beliefs import Hypothesis
from ..schemas.chains import AttackChain, ChainStep
from ..schemas.findings import Finding, FindingState

_log = get_logger("agent.web_chain")

#: Canonical escalation paths keyed by the entry vulnerability class. Each is the
#: sequence of rungs a human operator would walk from that class to a foothold.
#: The entry rung binds to the real entry belief; downstream rungs are the planned
#: path (pursued and proven as the campaign advances).
_CHAIN_TEMPLATES: dict[str, tuple[tuple[str, str], ...]] = {
    "open-redirect": (
        ("open-redirect", "Attacker-controlled redirect target"),
        ("ssrf", "Bend the redirect inward to reach internal services"),
        ("cloud-metadata", "Point the request at the cloud metadata endpoint (169.254.169.254)"),
        ("credential-access", "Read instance-role credentials from metadata"),
        ("foothold", "Use the stolen role credentials to operate as the workload"),
    ),
    "ssrf": (
        ("ssrf", "Forced server-side outbound request"),
        ("cloud-metadata", "Point the request at the cloud metadata endpoint (169.254.169.254)"),
        ("credential-access", "Read instance-role credentials from metadata"),
        ("foothold", "Use the stolen role credentials to operate as the workload"),
    ),
    "lfi": (
        ("lfi", "Arbitrary file read"),
        ("source-disclosure", "Read app source / config for secrets"),
        ("credential-access", "Recover DB/API credentials from disclosed config"),
        ("foothold", "Authenticate with recovered credentials"),
    ),
    "ssti": (
        ("ssti", "Template expression evaluation"),
        ("rce", "Escalate template evaluation to command execution"),
        ("foothold", "Open a session from the command-execution primitive"),
    ),
    "cmdi": (
        ("cmdi", "OS command injection in a web parameter"),
        ("foothold", "Arbitrary command execution on the host = initial web foothold"),
    ),
    "sqli": (
        ("sqli", "Database query injection"),
        ("credential-dump", "Extract credential hashes from the database"),
        ("auth-bypass", "Crack/replay a credential to authenticate"),
        ("foothold", "Operate as the compromised account"),
    ),
}

#: Minimum entry-belief confidence to bother laying out a chain from it.
_DEFAULT_MIN_CONFIDENCE = 0.5


def _objective_for(kind: str, template: tuple[tuple[str, str], ...]) -> str:
    rungs = "→".join(k for k, _ in template[1:]) or "impact"
    return f"web foothold via {kind}→{rungs}"


class WebChainer:
    """Composes attack chains from strong web beliefs and tracks their progress."""

    def __init__(self, *, created_by: str = "web-chainer") -> None:
        self._created_by = created_by

    def compose(
        self, wm: WorldModel, *, min_confidence: float = _DEFAULT_MIN_CONFIDENCE
    ) -> list[AttackChain]:
        """Lay out a chain for each strong entry belief that heads a template.

        Idempotent: an entry that already has a chain for the same objective is
        refreshed (rungs re-checked against confirmed findings), not duplicated.
        """

        composed: list[AttackChain] = []
        # Entry beliefs = active leads plus already-graduated ones (a confirmed
        # entry is the strongest possible start), highest-confidence first.
        for h in self._entry_candidates(wm):
            template = _CHAIN_TEMPLATES.get(h.kind)
            if template is None or h.confidence < min_confidence:
                continue
            objective = _objective_for(h.kind, template)
            existing = wm.find_chain(entry_subject=h.subject, objective=objective)
            if existing is not None:
                composed.append(self._refresh_one(wm, existing))
                continue
            chain = AttackChain(
                engagement_id=wm.engagement_id,
                objective=objective,
                entry_subject=h.subject,
                steps=self._steps_for(h, template),
                created_by=self._created_by,
            )
            composed.append(self._refresh_one(wm, wm.put_chain(chain)))
            _log.debug("chain composed", chain=chain.id, objective=objective, depth=chain.depth)
        return composed

    def refresh(self, wm: WorldModel) -> list[AttackChain]:
        """Re-mark every chain's rungs against the current confirmed findings."""

        return [self._refresh_one(wm, c) for c in wm.chains()]

    # --- internals ------------------------------------------------------------

    def _entry_candidates(self, wm: WorldModel) -> list[Hypothesis]:
        # Active leads are ranked; also consider graduated ones (finding_id set)
        # so a confirmed entry vuln still seeds/advances its chain.
        active = wm.open_hypotheses()
        graduated = [h for h in wm.hypotheses() if h.finding_id is not None]
        return active + graduated

    def _steps_for(
        self, entry: Hypothesis, template: tuple[tuple[str, str], ...]
    ) -> tuple[ChainStep, ...]:
        steps: list[ChainStep] = []
        for order, (kind, rationale) in enumerate(template):
            if order == 0:
                steps.append(ChainStep(
                    order=0, kind=kind, subject=entry.subject, rationale=rationale,
                    hypothesis_id=entry.id, finding_id=entry.finding_id,
                ))
            else:
                steps.append(ChainStep(
                    order=order, kind=kind, subject=entry.subject, rationale=rationale,
                ))
        return tuple(steps)

    def _refresh_one(self, wm: WorldModel, chain: AttackChain) -> AttackChain:
        confirmed = self._confirmed_findings(wm)
        steps = tuple(self._mark(step, confirmed) for step in chain.steps)
        return wm.put_chain(chain.model_copy(update={"steps": steps}))

    @staticmethod
    def _mark(step: ChainStep, confirmed: list[Finding]) -> ChainStep:
        """Light up a rung if a confirmed finding of its class exists on its host.

        A rung matches when a CONFIRMED finding's class set includes the rung's
        class and the finding's asset appears in the rung subject — so proving the
        SSRF lights up the SSRF rung, and proving command execution lights up both
        the ``cmdi`` rung and the ``foothold`` rung (RCE *is* the foothold).
        """

        if step.confirmed:
            return step
        for f in confirmed:
            if step.kind in _rung_classes(f.type) and f.asset in step.subject:
                return step.model_copy(update={"confirmed": True, "finding_id": f.id})
        return step

    @staticmethod
    def _confirmed_findings(wm: WorldModel) -> list[Finding]:
        store = wm.store
        return list(store.findings(FindingState.CONFIRMED)) if store is not None else []


#: Finding-type prefix → the chain rung class(es) it proves. Command execution
#: proves both its own rung and the foothold rung (arbitrary RCE = a foothold).
_FINDING_TYPE_TO_RUNGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sqli",)),
    ("ssti", ("ssti",)),
    ("template-injection", ("ssti",)),
    ("lfi", ("lfi",)),
    ("path-traversal", ("lfi",)),
    ("ssrf", ("ssrf",)),
    ("open-redirect", ("open-redirect",)),
    ("command-injection", ("cmdi", "rce", "foothold")),
    ("cmdi", ("cmdi", "rce", "foothold")),
    ("os-command", ("cmdi", "rce", "foothold")),
    ("rce", ("rce", "foothold")),
)


def _rung_classes(finding_type: str) -> tuple[str, ...]:
    """Map a finding type to the chain-rung class(es) it confirms."""

    for prefix, rungs in _FINDING_TYPE_TO_RUNGS:
        if finding_type.startswith(prefix):
            return rungs
    return (finding_type,)
