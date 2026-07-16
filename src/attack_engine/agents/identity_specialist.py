"""Identity / Active Directory specialist on the reasoning loop (Phase E).

The internal-network analogue of the Recon and Web specialists: where they map
hosts and web surface, this one maps the *identity* surface and reasons toward
Domain Admin. It collects the domain (BloodHound), finds credential leads
(Kerberoast / AS-REP), and folds what it learns into the shared world model's
**identity attack graph** — the BloodHound-style graph whose cheapest path from an
owned principal to a high-value target (Domain Admins / the domain object) is the
kill chain an operator walks.

Proposal-space only (rule #1): the specialist collects and reasons; it *proposes*
the path. Confirming a hop worked (a crack, a DCSync, an ADCS enrolment) is the
credential-lifecycle / execution layer's job, gated and audited. Everything flows
through the Tool Runner boundary, so scope/rate/RoE hold.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from ..schemas.beliefs import Observation
from ..schemas.tools import ToolResult
from .actions import ActionOutcome, ProposedAction
from .context import AgentContext
from .reasoning import LlmPlanner, LoopContext, ReasoningLoop
from .tool_actor import ToolRunnerActor

_log = get_logger("agent.identity")

#: Identity tools this specialist may reach for (must map to real wrappers).
DEFAULT_IDENTITY_TOOLS: tuple[str, ...] = ("bloodhound", "kerberoast")

IDENTITY_SYSTEM_PROMPT = (
    "You are the Identity / Active Directory specialist of an authorized red-team "
    "engagement. From a foothold inside the network, you map the identity surface "
    "and find the cheapest path to Domain Admin. Collect the domain with BloodHound; "
    "find roastable accounts (Kerberoast / AS-REP); reason about ACL abuse, DCSync, "
    "delegation (constrained / RBCD), shadow credentials and ADCS (ESC1/ESC8) as "
    "routes to a high-value target. You only observe and propose — you never claim a "
    "hop succeeded; the credential-lifecycle and execution layers confirm it under a "
    "gate. Propose the ranked next actions as tool calls against in-scope domain hosts."
)


class ADObserver:
    """Folds identity tool output into the world model's AD attack graph + beliefs."""

    def observe(self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext) -> None:
        result = outcome.raw
        if not outcome.ok or not isinstance(result, ToolResult):
            return
        wm = ctx.world_model
        if action.tool == "bloodhound":
            self._ingest_bloodhound(wm, result)
        elif action.tool == "kerberoast":
            self._ingest_kerberoast(wm, result, action)

    def _ingest_bloodhound(self, wm: WorldModel, result: ToolResult) -> None:
        # A collector that emits normalized graph data (users/groups/aces…) lets us
        # rebuild the graph; the stock wrapper emits only counts, in which case we
        # simply re-surface any path the graph already holds.
        data = result.parsed.get("data")
        if isinstance(data, dict):
            self.ingest_collection(wm, data)
        else:
            self._surface_paths(wm, source="bloodhound")

    def _ingest_kerberoast(
        self, wm: WorldModel, result: ToolResult, action: ProposedAction
    ) -> None:
        parsed = result.parsed
        if not parsed.get("roastable"):
            return
        params = action.params or {}
        principal = str(params.get("account") or parsed.get("account") or action.target)
        asrep = parsed.get("kind") == "asrep" or params.get("mode") == "asrep"
        wm.ad_graph.mark_roastable(principal, asrep=asrep)
        technique = "AS-REP" if asrep else "Kerberoast"
        obs = Observation(source="kerberoast", probability=0.7, note=f"raw:{result.audit_id}")
        existing = wm.find_hypothesis(kind="ad-credential", subject=principal)
        if existing is not None:
            wm.observe(existing.id, obs)
            return
        wm.add_hypothesis(
            subject=principal, kind="ad-credential",
            title=f"{principal} is {technique}-roastable",
            rationale=f"{technique} account — request its ticket and crack it offline to own it.",
            prior=0.5, suggested_tools=("hashcat",), created_by="identity",
            observations=(obs,),
        )

    # --- collection ingestion (the tested + future file-artifact entry) --------

    @classmethod
    def ingest_collection(
        cls, wm: WorldModel, data: dict[str, Any], *, owned: Sequence[str] = ()
    ) -> None:
        """Build the identity attack graph from normalized BloodHound-shape data,
        mark owned principals, and surface any path to a high-value target."""

        from ..ad.collect import from_bloodhound

        wm.set_ad_graph(from_bloodhound(data))
        for principal in owned:
            wm.mark_owned(principal)
        cls._surface_paths(wm, source="bloodhound")

    @staticmethod
    def _surface_paths(wm: WorldModel, *, source: str) -> None:
        for path in wm.domain_admin_paths():
            subject = f"{path.start}=>{path.target}"
            obs = Observation(source=source, probability=0.85, note=f"cost:{path.cost}")
            existing = wm.find_hypothesis(kind="ad-path", subject=subject)
            if existing is not None:
                wm.observe(existing.id, obs)
                continue
            wm.add_hypothesis(
                subject=subject, kind="ad-path",
                title=(f"Identity path to {path.target} "
                       f"({len(path.edges)} hops, cost {path.cost:.1f})"),
                rationale=" → ".join(e.edge_type.value for e in path.edges),
                prior=0.6, suggested_tools=("impacket", "certipy", "hashcat"),
                created_by="identity", observations=(obs,),
            )


def build_identity_loop(
    ctx: AgentContext,
    *,
    tools: Sequence[str] | None = None,
    tier: ModelTier = ModelTier.FRONTIER,
    max_steps: int = 20,
) -> ReasoningLoop:
    """Assemble the Identity/AD specialist's reasoning loop.

    Plans with the model gateway, acts through the Tool Runner, and observes
    identity output into the world model's AD attack graph. Drive it toward the
    :class:`~attack_engine.orchestrator.objective.DomainAdminObjective` with the
    :class:`~attack_engine.orchestrator.controller.ObjectiveController`.
    """

    if ctx.gateway is None:
        raise ValueError("identity loop requires a model gateway in the AgentContext")
    planner = LlmPlanner(
        ctx.gateway,
        tools=list(tools or DEFAULT_IDENTITY_TOOLS),
        system_prompt=IDENTITY_SYSTEM_PROMPT,
        tier=tier,
        actor_name="identity",
        engagement_id=ctx.engagement_id,
    )
    return ReasoningLoop(
        planner,
        ToolRunnerActor(ctx.tool_runner),
        ADObserver(),
        max_steps=max_steps,
    )
