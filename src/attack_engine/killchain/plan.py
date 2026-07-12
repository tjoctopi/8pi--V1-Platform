"""Goal-directed kill-chain planning (kill-chain diagram, phases 1 & 3–7).

Builds the privilege graph from the engagement's *confirmed* footholds, adds the
*candidate* transitions an attacker would attempt (privilege escalation on an
owned host, lateral movement to reachable hosts), and computes the cheapest
route from entry to the objective. Confirmed edges are real (an exploit we
proved); candidate edges are clearly marked as planned — the engine never
pretends an unconfirmed step happened. Impact phases are flagged as gated.

This is planning only: it reasons about the attack, it does not execute it.
"""

from __future__ import annotations

from enum import Enum

from ..attack.catalog import technique_for_finding_type
from ..knowledge.store import KnowledgeStore
from ..schemas.common import StrictModel
from ..schemas.findings import FindingState, Priority
from .graph import ENTRY, ExploitEdge, Position, PrivilegeGraph


class KillChainPhase(str, Enum):
    INITIAL_ACCESS = "initial_access"           # entry → user     (gated)
    PRIVILEGE_ESCALATION = "privilege_escalation"  # user → root    (gated)
    LATERAL_MOVEMENT = "lateral_movement"       # root → other host (gated)
    OBJECTIVE = "objective"                      # reach crown jewel (gated)


#: Every impact phase requires a human gate (kill-chain diagram, steps 4–7).
GATED_PHASES = frozenset(KillChainPhase)

#: Which tools a gated step *would* use, for the plan/report — purely
#: informational labels. The engine does not autonomously run post-exploitation
#: tooling; these steps are human-gated and operator-driven.
_SUGGESTED_TOOLS = {
    "T1190": "metasploit-check · sqlmap · nuclei",
    "T1059": "command-injection module (time-blind)",
    "T1221": "ssti module (math oracle)",
    "T1078": "default-credentials module · hydra",
    "T1068": "linpeas/winpeas · GTFOBins · sudo/kernel checks",
    "T1021": "crackmapexec · bloodhound · ssh pivot",
}


class KillChainStep(StrictModel):
    phase: KillChainPhase
    technique: str
    name: str
    from_position: str
    to_position: str
    cost: float
    gated: bool
    #: True when this step corresponds to a confirmed exploit; False = planned.
    confirmed: bool
    #: Informational: the tooling a human operator would use for this step.
    suggested_tools: str = ""
    finding_id: str | None = None


class KillChainPlan(StrictModel):
    goal: str
    reachable: bool
    total_cost: float = 0.0
    steps: list[KillChainStep] = []
    #: True when every step in the route is a confirmed exploit (fully proven).
    fully_confirmed: bool = False

    def to_markdown(self) -> str:
        if not self.reachable:
            return f"**Objective {self.goal} — no route found.**"
        status = "fully confirmed" if self.fully_confirmed else "planned (some steps unconfirmed)"
        lines = [f"**Objective {self.goal}** — {status}, cost {self.total_cost:.1f}", ""]
        for i, s in enumerate(self.steps, 1):
            tag = "confirmed" if s.confirmed else "planned"
            # Impact-class phases gate to a human UNLESS the signed RoE
            # pre-authorized them at the engagement boundary (autonomy tier ≥ 1).
            gate = " [impact — gated unless authorized]" if s.gated else ""
            lines.append(
                f"{i}. **{s.phase.value}** ({s.technique}, {tag}){gate}: "
                f"{s.from_position} → {s.to_position} — {s.name}"
            )
        return "\n".join(lines)


def _phase_for(src_priv: str, dst_host: str, src_host: str, dst_priv: str) -> KillChainPhase:
    if src_priv == "none":
        return KillChainPhase.INITIAL_ACCESS
    if src_host == dst_host and dst_priv in ("root", "admin", "domain_admin"):
        return KillChainPhase.PRIVILEGE_ESCALATION
    return KillChainPhase.LATERAL_MOVEMENT


def build_privilege_graph(
    store: KnowledgeStore, *, goal: tuple[str, str] | None = None
) -> PrivilegeGraph:
    """Assemble the attacker's privilege graph from confirmed findings + candidates."""

    graph = PrivilegeGraph()
    confirmed = [
        f for f in store.findings(FindingState.CONFIRMED)
        if f.priority is not Priority.INFORMATIONAL and f.reachable
    ]
    foothold_hosts: set[str] = set()
    for f in confirmed:
        technique = str(f.metadata.get("technique") or technique_for_finding_type(f.type))
        # Confirmed initial access: entry → (host, user).
        graph.add_exploit(ExploitEdge(
            src=ENTRY, dst=(f.asset, "user"), technique=technique,
            name=f"{f.type} on {f.asset}",
            cost=round(1.0 / (f.exploit_prob or 0.5), 2),
            finding_id=f.id,
        ))
        foothold_hosts.add(f.asset)

    # Candidate transitions the attacker would attempt. We only lay these down
    # once at least one confirmed foothold exists (entry has a way in).
    all_hosts = {a.address for a in store.assets()} | foothold_hosts
    if goal is not None:
        all_hosts.add(goal[0])
    if foothold_hosts:
        for host in all_hosts:
            # Privilege escalation on any owned host (planned, not yet confirmed).
            graph.add_exploit(ExploitEdge(
                src=(host, "user"), dst=(host, "root"), technique="T1068",
                name=f"local privilege escalation on {host} (candidate)", cost=3.0,
            ))
            # Lateral movement from root to every other reachable internal host.
            for other in all_hosts - {host}:
                graph.add_exploit(ExploitEdge(
                    src=(host, "root"), dst=(other, "user"), technique="T1021",
                    name=f"lateral movement {host} → {other} (candidate)", cost=4.0,
                ))
    if goal is not None:
        graph.set_goal(*goal)
    return graph


class KillChainPlanner:
    """Plans the cheapest route to an objective over the privilege graph."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def plan(self, goal_host: str, goal_privilege: str = "root") -> KillChainPlan:
        goal = (goal_host, goal_privilege)
        graph = build_privilege_graph(self._store, goal=goal)
        chain = graph.cheapest_path(goal)
        if chain is None:
            return KillChainPlan(goal=Position(*goal).label(), reachable=False)

        steps: list[KillChainStep] = []
        for edge in chain:
            src_host, src_priv = edge.src
            dst_host, dst_priv = edge.dst
            phase = _phase_for(src_priv, dst_host, src_host, dst_priv)
            steps.append(KillChainStep(
                phase=phase,
                technique=edge.technique,
                name=edge.name,
                from_position=Position(*edge.src).label(),
                to_position=Position(*edge.dst).label(),
                cost=edge.cost,
                gated=phase in GATED_PHASES,
                confirmed=edge.finding_id is not None,
                suggested_tools=_SUGGESTED_TOOLS.get(edge.technique, ""),
                finding_id=edge.finding_id,
            ))
        # The final hop of a multi-step route reaches the crown jewel: OBJECTIVE.
        if len(steps) > 1:
            steps[-1] = steps[-1].model_copy(update={"phase": KillChainPhase.OBJECTIVE})
        return KillChainPlan(
            goal=Position(*goal).label(),
            reachable=True,
            total_cost=round(sum(s.cost for s in steps), 2),
            steps=steps,
            fully_confirmed=all(s.confirmed for s in steps),
        )
