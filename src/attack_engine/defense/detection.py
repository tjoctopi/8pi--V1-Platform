"""Evasion & detection testing — the purple-team "did the SOC catch us?" (O6).

The offensive side of the platform records every action in the immutable audit
log. This module turns that record into a *defensive* measurement: given a
detection ruleset (ATT&CK-mapped signatures a blue team would deploy), which of
the techniques we executed would have fired a detection, and which slipped
through? The output is a detection-coverage report — the actual deliverable of
authorized adversary emulation. It never evades for its own sake; it measures.

Detections operate on the audit trail (what happened), independent of the RoE
authorization (which is *why* it was allowed) — so an authorized-but-noisy attack
still counts as "detected", exactly as a real SOC would see it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..governance.audit import AuditEntry
from ..schemas.common import StrictModel

#: A rule inspects the engagement's audit entries and returns whether it fired.
RuleFn = Callable[[list[AuditEntry]], bool]


@dataclass(frozen=True)
class DetectionRule:
    """An ATT&CK-mapped detection a blue team would run against the telemetry."""

    id: str
    name: str
    technique: str      # the ATT&CK technique this rule detects
    fires: RuleFn       # predicate over the audit trail


def _tool_used(*tools: str) -> RuleFn:
    names = set(tools)
    def _fn(entries: list[AuditEntry]) -> bool:
        return any(
            e.action == "tool.run" and e.payload.get("tool") in names for e in entries
        )
    return _fn


def _action_seen(*actions: str) -> RuleFn:
    wanted = set(actions)
    def _fn(entries: list[AuditEntry]) -> bool:
        return any(e.action in wanted for e in entries)
    return _fn


def _tool_count_over(tool: str, threshold: int) -> RuleFn:
    def _fn(entries: list[AuditEntry]) -> bool:
        n = sum(1 for e in entries if e.action == "tool.run" and e.payload.get("tool") == tool)
        return n >= threshold
    return _fn


def default_detection_ruleset() -> list[DetectionRule]:
    """A starter blue-team ruleset mapping telemetry patterns to ATT&CK techniques.

    Illustrative but real: each rule keys off audited offensive activity a SOC
    would have visibility into (tool execution, exploit confirmation, post-ex
    commands, credential requests). Extend per environment.
    """

    return [
        DetectionRule("DR-SCAN", "High-volume network scanning", "T1595",
                      _tool_count_over("nmap", 1)),
        DetectionRule("DR-WEBFUZZ", "Web content brute-forcing", "T1083",
                      _tool_used("ffuf", "katana")),
        DetectionRule("DR-VULNSCAN", "Vulnerability scanner traffic", "T1595.002",
                      _tool_used("nuclei", "nikto")),
        DetectionRule("DR-EXPLOIT", "Exploitation of public-facing app", "T1190",
                      _action_seen("exploit.confirm")),
        DetectionRule("DR-MSF", "Metasploit exploitation / session", "T1210",
                      _tool_used("metasploit")),
        DetectionRule("DR-POSTEX", "Post-exploitation command execution", "T1059",
                      _action_seen("c2.postex")),
        DetectionRule("DR-LATERAL", "Lateral movement / pivot", "T1021",
                      _action_seen("c2.pivot")),
        DetectionRule("DR-ADENUM", "Active Directory enumeration", "T1087",
                      _tool_used("bloodhound")),
        DetectionRule("DR-KERB", "Kerberoasting / AS-REP roasting", "T1558.003",
                      _tool_used("kerberoast")),
    ]


class DetectionResult(StrictModel):
    technique: str
    rule_id: str
    rule_name: str
    detected: bool


class DetectionReport(StrictModel):
    """Per-technique detection outcome for an emulation run."""

    results: list[DetectionResult] = []

    @property
    def detected(self) -> list[str]:
        return sorted({r.technique for r in self.results if r.detected})

    @property
    def evaded(self) -> list[str]:
        det = set(self.detected)
        return sorted({r.technique for r in self.results if not r.detected} - det)

    @property
    def coverage(self) -> float:
        techniques = {r.technique for r in self.results}
        if not techniques:
            return 0.0
        return round(len(self.detected) / len(techniques), 4)

    def to_markdown(self) -> str:
        lines = [
            "## Detection coverage (purple-team)",
            "",
            f"- Techniques exercised: {len({r.technique for r in self.results})}  ·  "
            f"detected: **{len(self.detected)}**  ·  evaded: {len(self.evaded)}  ·  "
            f"coverage: **{self.coverage * 100:.0f}%**",
            "",
            "| Rule | Technique | Detected |",
            "|---|---|---|",
        ]
        for r in self.results:
            lines.append(
                f"| {r.rule_name} | {r.technique} | {'✅ yes' if r.detected else '❌ EVADED'} |"
            )
        return "\n".join(lines) + "\n"


@dataclass
class DetectionTester:
    """Runs a detection ruleset against an engagement's audit trail."""

    ruleset: list[DetectionRule] = field(default_factory=default_detection_ruleset)

    def evaluate(self, audit_entries: list[AuditEntry]) -> DetectionReport:
        """Report which mapped techniques the telemetry would have detected.

        Only rules whose underlying activity actually occurred are reported —
        i.e. techniques we *exercised*; a rule that can't have fired because we
        never did the thing is not counted as an evasion.
        """

        results: list[DetectionResult] = []
        for rule in self.ruleset:
            fired = rule.fires(audit_entries)
            # A rule contributes to the report only if its activity is present in
            # the trail (exercised). We approximate "exercised" as: the rule fired
            # (activity happened → detected) — undetected techniques come from an
            # explicit exercised set via evaluate_for().
            if fired:
                results.append(DetectionResult(
                    technique=rule.technique, rule_id=rule.id,
                    rule_name=rule.name, detected=True))
        return DetectionReport(results=results)

    def evaluate_for(
        self, audit_entries: list[AuditEntry], exercised: set[str]
    ) -> DetectionReport:
        """Report detection over an explicit set of *exercised* techniques.

        For each exercised technique, a matching rule that fires ⇒ detected;
        otherwise it is an evasion (the SOC missed a technique we ran).
        """

        by_technique: dict[str, list[DetectionRule]] = {}
        for rule in self.ruleset:
            by_technique.setdefault(rule.technique, []).append(rule)
        results: list[DetectionResult] = []
        for technique in sorted(exercised):
            rules = by_technique.get(technique, [])
            detected = any(r.fires(audit_entries) for r in rules)
            matched: DetectionRule | None = rules[0] if rules else None
            results.append(DetectionResult(
                technique=technique,
                rule_id=matched.id if matched else "—",
                rule_name=matched.name if matched else "no detection rule",
                detected=detected,
            ))
        return DetectionReport(results=results)
