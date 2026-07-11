"""Engagement report (spec §3 step 7 — "report generated").

A structured, serialisable summary of the run: the asset inventory, findings by
state and priority, proposed remediations, re-test outcomes, Blue Sentry alerts,
and the audit-chain attestation. Rendered to Markdown for humans. The report is
evidence-linked — every confirmed finding points back to audit ids — so a
regulated buyer can trace any claim to its raw record.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..intel.surface import AttackSurface
from ..killchain.plan import _TECHNIQUE_BY_TYPE, KillChainPlan
from ..schemas.common import StrictModel, iso_now
from ..schemas.findings import VULN_TYPE_PREFIXES, Finding, FindingState, Priority
from ..schemas.remediation import Remediation, RetestResult
from .attackpath import AttackChain

_PRIORITY_RANK = {
    Priority.PATCH_IMMEDIATELY: 0,
    Priority.HIGH: 1,
    Priority.MEDIUM: 2,
    Priority.LOW: 3,
    Priority.INFORMATIONAL: 4,
}
_PRIORITY_RANK_STR = {p.value: rank for p, rank in _PRIORITY_RANK.items()}


class RiskMapEntry(StrictModel):
    """One row of the reachability-prioritised risk map."""

    asset: str
    type: str
    reachable: bool
    on_kev: bool
    exploit_prob: float | None
    priority: str
    #: Reachability-gated risk score (0 for unreachable — cannot be reached to
    #: exploit, so it cannot top the map regardless of CVSS).
    risk: float


class BreachFoothold(StrictModel):
    """One confirmed, reachable way into the estate — an initial-access vector."""

    asset: str
    finding_type: str
    technique: str  # MITRE ATT&CK id (best-effort)
    exploit_prob: float | None
    on_kev: bool
    #: Entry → … → asset node sequence (from the attack graph), if computed.
    entry_path: list[str]
    #: Audit-log pointers proving the confirmation (evidence-linked).
    evidence: list[str]
    finding_id: str


class BreachVerdict(StrictModel):
    """The headline answer: *is this target breachable, and how?*

    ``breachable`` is True iff at least one finding is **confirmed** (oracle-
    verified + correlated), an actual access vector (a vulnerability, a KEV CVE,
    or a high/patch-now issue), **and** on a reachable asset — i.e. a route an
    attacker could actually take, not a theoretical one.
    """

    breachable: bool
    footholds: list[BreachFoothold] = []

    def summary(self) -> str:
        if not self.breachable:
            return (
                "NOT BREACHABLE from the tested surface — no confirmed, reachable "
                "access vector was proven (this is not a guarantee of safety; it is "
                "the evidence-backed result of this engagement's checks)."
            )
        n = len(self.footholds)
        assets = sorted({fh.asset for fh in self.footholds})
        return (
            f"BREACHABLE — {n} confirmed, reachable access "
            f"vector{'s' if n != 1 else ''} on {len(assets)} asset(s): "
            f"{', '.join(assets)}."
        )

    def to_markdown(self) -> str:
        lines = ["## Breachability verdict", "", f"**{self.summary()}**", ""]
        if not self.footholds:
            return "\n".join(lines) + "\n"
        lines.append("| Access vector | Asset | Technique | KEV | Exploit prob | Route |")
        lines.append("|---|---|---|---|---|---|")
        for fh in self.footholds:
            prob = f"{fh.exploit_prob:.2f}" if fh.exploit_prob is not None else "—"
            route = " → ".join(fh.entry_path) if fh.entry_path else fh.asset
            lines.append(
                f"| {fh.finding_type} | {fh.asset} | {fh.technique} | "
                f"{'yes' if fh.on_kev else '—'} | {prob} | {route} |"
            )
        return "\n".join(lines) + "\n"


def _is_access_vector(f: Finding) -> bool:
    """Whether a confirmed finding constitutes an initial-access vector."""

    return (
        f.type.startswith(VULN_TYPE_PREFIXES)
        or f.on_kev
        or f.priority in (Priority.PATCH_IMMEDIATELY, Priority.HIGH)
    )


def build_breach_verdict(
    confirmed: list[Finding], attack_paths: list[AttackChain]
) -> BreachVerdict:
    """Synthesise the breachability verdict from confirmed footholds + reachability."""

    chain_by_asset = {c.target: c for c in attack_paths}
    footholds: list[BreachFoothold] = []
    for f in confirmed:
        if f.priority is Priority.INFORMATIONAL or not _is_access_vector(f):
            continue
        chain = chain_by_asset.get(f.asset)
        reachable = chain.reachable if chain is not None else f.reachable
        if not reachable:
            continue  # a vector we cannot reach is not a breach path
        technique = str(f.metadata.get("technique") or _TECHNIQUE_BY_TYPE.get(f.type, "T1190"))
        footholds.append(
            BreachFoothold(
                asset=f.asset,
                finding_type=f.type,
                technique=technique,
                exploit_prob=f.exploit_prob,
                on_kev=f.on_kev,
                entry_path=chain.path if chain is not None else [f.asset],
                evidence=list(f.evidence),
                finding_id=f.id,
            )
        )
    footholds.sort(key=lambda fh: -(fh.exploit_prob or 0.0))
    return BreachVerdict(breachable=bool(footholds), footholds=footholds)


class EngagementReport(StrictModel):
    engagement_id: str
    generated_at: str
    goal: str = "assess"
    asset_count: int = 0
    findings_by_state: dict[str, int] = {}
    findings_by_priority: dict[str, int] = {}
    confirmed: list[Finding] = []
    breach: BreachVerdict = BreachVerdict(breachable=False)
    attack_surface: AttackSurface | None = None
    risk_map: list[RiskMapEntry] = []
    attack_paths: list[AttackChain] = []
    kill_chain: KillChainPlan | None = None
    hardening_actions: list[str] = []
    remediations: list[Remediation] = []
    retests: list[RetestResult] = []
    escalations: list[str] = []  # finding ids that failed re-test
    blue_alerts: int = 0
    audit_entries: int = 0
    audit_intact: bool = True
    audit_head: str | None = None

    def to_markdown(self) -> str:
        lines: list[str] = [
            f"# Engagement Report — {self.engagement_id}",
            "",
            f"- Generated: {self.generated_at}",
            f"- Goal: {self.goal}",
            f"- Assets: {self.asset_count}",
            f"- Audit: {self.audit_entries} entries · "
            f"chain {'intact ✅' if self.audit_intact else 'BROKEN ❌'}"
            + (f" · head `{self.audit_head[:12]}…`" if self.audit_head else ""),
            f"- Blue Sentry alerts: {self.blue_alerts}",
            "",
            self.breach.to_markdown(),
        ]
        if self.attack_surface is not None and self.attack_surface.total_leads:
            lines += [
                "## Attack-surface intelligence (offensive leads)",
                "",
                f"{self.attack_surface.total_leads} attack leads "
                f"({self.attack_surface.confirmed_leads} confirmed) across "
                f"{len(self.attack_surface.assets)} asset(s) — full dossier via "
                "`attack-engine intel`.",
                "",
            ]
        lines += ["## Risk map (reachability-prioritised)", ""]
        if not self.risk_map:
            lines.append("_No confirmed risk._")
        else:
            lines.append("| Risk | Priority | Type | Asset | Reachable | KEV | Exploit prob |")
            lines.append("|---|---|---|---|---|---|---|")
            for e in self.risk_map:
                prob = f"{e.exploit_prob:.2f}" if e.exploit_prob is not None else "—"
                lines.append(
                    f"| {e.risk:.2f} | {e.priority} | {e.type} | {e.asset} | "
                    f"{'yes' if e.reachable else 'no'} | {'yes' if e.on_kev else '—'} | {prob} |"
                )
        lines += ["", "## Attack paths (kill chains)", ""]
        if not self.attack_paths:
            lines.append("_No exploitable path confirmed._")
        else:
            for c in self.attack_paths:
                arrow = " → ".join(c.path)
                lines.append(
                    f"- **{c.score:.2f}** [{'reachable' if c.reachable else 'unreachable'}] "
                    f"{arrow}  ·  via {', '.join(c.techniques)}"
                )
        if self.kill_chain is not None:
            lines += ["", "## Kill chain to objective", "", self.kill_chain.to_markdown()]
        lines += ["", "## Hardening actions", ""]
        if not self.hardening_actions:
            lines.append("_None._")
        for action in self.hardening_actions:
            lines.append(f"- {action}")
        lines += ["", "## Proposed remediations", ""]
        if not self.remediations:
            lines.append("_None._")
        for r in self.remediations:
            lines.append(
                f"- **{r.title}** ({r.kind.value}, {r.status.value}) "
                f"— finding `{r.finding_id}`"
            )
        if self.retests:
            lines += ["", "## Re-test outcomes", ""]
            for rt in self.retests:
                verdict = "fixed ✅" if rt.fixed else "PERSISTED ❌ (escalated)"
                lines.append(f"- `{rt.finding_id}`: {verdict} — {rt.detail}")
        lines.append("")
        return "\n".join(lines)


@dataclass
class _Counters:
    by_state: dict[str, int] = field(default_factory=dict)
    by_priority: dict[str, int] = field(default_factory=dict)


def build_report(
    *,
    engagement_id: str,
    goal: str,
    findings: list[Finding],
    remediations: list[Remediation],
    asset_count: int,
    audit_entries: int,
    audit_intact: bool,
    audit_head: str | None,
    retests: list[RetestResult] | None = None,
    blue_alerts: int = 0,
    attack_paths: list[AttackChain] | None = None,
    kill_chain: KillChainPlan | None = None,
    attack_surface: AttackSurface | None = None,
) -> EngagementReport:
    counters = _Counters()
    for f in findings:
        counters.by_state[f.state.value] = counters.by_state.get(f.state.value, 0) + 1
        if f.priority is not None:
            counters.by_priority[f.priority.value] = (
                counters.by_priority.get(f.priority.value, 0) + 1
            )

    confirmed = sorted(
        (f for f in findings if f.state is FindingState.CONFIRMED),
        key=lambda f: (
            _PRIORITY_RANK.get(f.priority, 9) if f.priority else 9,
            -(f.exploit_prob or 0.0),
        ),
    )
    retests = retests or []
    escalations = [rt.finding_id for rt in retests if not rt.fixed]

    # Reachability-prioritised risk map: risk is the exploit probability, zeroed
    # for unreachable findings (they cannot be reached to exploit).
    risk_map = [
        RiskMapEntry(
            asset=f.asset,
            type=f.type,
            reachable=f.reachable,
            on_kev=f.on_kev,
            exploit_prob=f.exploit_prob,
            priority=f.priority.value if f.priority else "n/a",
            risk=round((f.exploit_prob or 0.0) if f.reachable else 0.0, 4),
        )
        for f in confirmed
    ]
    risk_map.sort(key=lambda e: (-e.risk, _PRIORITY_RANK_STR.get(e.priority, 9)))
    hardening_actions = [r.title for r in remediations]
    breach = build_breach_verdict(confirmed, attack_paths or [])

    return EngagementReport(
        engagement_id=engagement_id,
        generated_at=iso_now(),
        goal=goal,
        asset_count=asset_count,
        findings_by_state=counters.by_state,
        findings_by_priority=counters.by_priority,
        confirmed=confirmed,
        breach=breach,
        attack_surface=attack_surface,
        risk_map=risk_map,
        attack_paths=attack_paths or [],
        kill_chain=kill_chain,
        hardening_actions=hardening_actions,
        remediations=remediations,
        retests=retests,
        escalations=escalations,
        blue_alerts=blue_alerts,
        audit_entries=audit_entries,
        audit_intact=audit_intact,
        audit_head=audit_head,
    )
