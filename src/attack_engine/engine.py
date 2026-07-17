"""Engine composition root.

Everything the engine needs is constructed here from :class:`Settings`, so no
component wires itself up. :class:`Engine` holds the process-wide services
(audit log, event bus, model gateway, sandbox, tool registry);
:meth:`Engine.engagement` binds them to a single signed :class:`Scope`,
producing an :class:`Engagement` that owns the per-engagement blackboard and
scope-enforcing Tool Runner and can run agents.

This is the seam the CLI and any future API server build on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from .c2.lateral import LateralClient, LateralMovementLauncher
    from .credentials.vault import CredentialVault
    from .exploit.runner import ExploitReport
    from .killchain.plan import KillChainPlan
    from .knowledge.graph_backend import GraphBackend
    from .orchestrator.orchestrator import Orchestrator

from .agents.base import Agent, AgentReport
from .agents.context import AgentContext
from .agents.loader import build_agent
from .c2.backend import C2Backend
from .c2.foothold import FootholdRunner
from .c2.postex import PostExOperator
from .c2.session import SessionManager
from .config import Settings, get_settings
from .correlate.feeds import CveFeed, LocalCveFeed
from .correlate.matcher import ExploitabilityMatcher, MatchReport
from .correlate.nvd import build_feed_from_files
from .correlate.scoring import ExploitabilityScorer
from .defense.blue_sentry import BlueSentry
from .errors import AttackEngineError
from .eventbus.base import EventBus
from .eventbus.factory import build_event_bus
from .gateway.router import ModelGateway
from .governance.audit import AuditLog
from .governance.audit_backends import build_audit_backend
from .governance.authorization import KillSwitch
from .governance.gates import HumanGate, Responder, deny_all
from .knowledge.store import KnowledgeStore
from .logging import configure_logging, get_logger
from .schemas.agentspec import AgentSpec
from .schemas.findings import FindingState
from .schemas.scope import Scope
from .toolrunner.registry import ToolRegistry, default_registry
from .toolrunner.runner import ToolRunner
from .toolrunner.sandbox import Sandbox, build_sandbox
from .verify.calibrate import Calibrator
from .verify.calibration import (
    CalibrationMethod,
    calibration_report,
    fit_calibrator,
    load_calibration_samples,
)
from .verify.context import VerifyContext
from .verify.oracles import default_oracle_registry
from .verify.verifier import Verifier, VerifyReport

_log = get_logger("engine")


def build_cve_feed(settings: Settings) -> CveFeed:
    """Select the CVE feed from config: real files when set, else the seed.

    Production sets ``cve_nvd_path`` + ``cve_kev_path`` (refreshed by a scheduled
    job) and gets the real NVD/KEV feed, enriched with EPSS + public-exploit ids
    when those paths are set too. With no files configured we fall back to the
    bundled 3-record seed — fine for dev/pilot, but we log loudly so a real
    deployment is never silently running on the toy feed.
    """

    if settings.cve_nvd_path and settings.cve_kev_path:
        _log.info(
            "loading CVE feed from files",
            nvd=settings.cve_nvd_path,
            kev=settings.cve_kev_path,
            epss=settings.cve_epss_path,
            exploit_ids=settings.cve_exploit_ids_path,
        )
        return build_feed_from_files(
            settings.cve_nvd_path,
            settings.cve_kev_path,
            epss_path=settings.cve_epss_path,
            exploit_ids_path=settings.cve_exploit_ids_path,
        )
    _log.warning("no CVE feed files configured; using bundled seed feed (dev/pilot only)")
    return LocalCveFeed.from_json()


def build_calibrator(settings: Settings) -> Calibrator | None:
    """Fit the exploitability calibrator from config, or None if not configured.

    With ``calibration_path`` set, exploit probabilities are mapped onto ground
    truth (honest "0.9 ≈ 90%"); without it, the raw model score is used and every
    consumer behaves exactly as before.
    """

    if not settings.calibration_path:
        return None
    method: CalibrationMethod = (
        "platt" if settings.calibration_method == "platt" else "isotonic"
    )
    samples = load_calibration_samples(settings.calibration_path)
    calibrator = fit_calibrator(samples, method)
    _log.info(
        "exploitability calibrator fitted",
        method=method,
        report=calibration_report(calibrator, samples),
    )
    return calibrator


def load_scope(path: str | Path) -> Scope:
    """Load and validate a signed engagement scope from YAML."""

    p = Path(path)
    if not p.exists():
        raise AttackEngineError(f"scope file not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AttackEngineError(f"scope file {p} must be a mapping")
    return Scope.model_validate(data)


@dataclass
class Engagement:
    """A live engagement: scope + blackboard + scope-enforcing Tool Runner.

    Exposes the three Sprint-1 stages — ``run_agent`` (recon/web/exploit),
    ``verify`` (accuracy gate), and ``correlate`` (exploitability scoring) — so
    a caller can drive the loop; the Orchestrator automates this in Sprint 2.
    """

    scope: Scope
    store: KnowledgeStore
    tool_runner: ToolRunner
    context: AgentContext
    registry: ToolRegistry
    audit: AuditLog
    feed: CveFeed
    scorer: ExploitabilityScorer
    #: C2 session/listener registry (O3) + the engagement kill switch (O0).
    session_manager: SessionManager
    kill_switch: KillSwitch
    #: Fitted probability calibrator (None ⇒ raw scores). Wired into the Verifier
    #: so a promoted finding's exploit_prob is calibrated, not a raw sigmoid.
    calibrator: Calibrator | None = None

    def run_agent(self, spec: AgentSpec, targets: list[str]) -> AgentReport:
        agent: Agent = build_agent(spec, self.context, self.registry)
        return agent.run(targets)

    def verify(self) -> VerifyReport:
        """Run the deterministic oracles over proposed findings (rule #1)."""

        ctx = VerifyContext(
            engagement_id=self.scope.engagement_id,
            tool_runner=self.tool_runner,
            store=self.store,
            audit=self.audit,
        )
        return Verifier(default_oracle_registry(), ctx, calibrator=self.calibrator).run()

    def correlate(self) -> MatchReport:
        """Map verified services to scored, prioritised CVE findings."""

        return ExploitabilityMatcher(
            self.feed, self.store, self.audit, scorer=self.scorer
        ).run()

    def exploit(self) -> ExploitReport:
        """Confirm exploitability of candidate findings — gated + audited.

        Runs the confirmation-grade exploit modules over any candidate finding
        they handle, behind the hard ``exploit_confirm`` gate. Bounded proofs
        only; no data extraction. Fails closed if no gate is wired.
        """

        from .exploit import ExploitRunner, default_exploit_registry
        from .governance.gates import HumanGate

        registry = default_exploit_registry()
        listener = self.session_manager.default_listener()
        ctx = VerifyContext(
            engagement_id=self.scope.engagement_id,
            tool_runner=self.tool_runner,
            store=self.store,
            audit=self.audit,
            listener_lhost=listener.host if listener else None,
        )
        gate = self.context.gate or HumanGate(self.audit)  # None ⇒ deny-all
        runner = ExploitRunner(
            registry, ctx, gate, event_bus=self.context.event_bus, scope=self.scope
        )
        candidates = [
            f
            for f in self.store.findings(FindingState.PROPOSED)
            if registry.for_finding(f)
        ]
        return runner.run(candidates)

    def kill_chain(self, goal_host: str, goal_privilege: str = "root") -> KillChainPlan:
        """Plan the cheapest goal-directed attack route from confirmed footholds.

        Planning only — reasons over the privilege graph to show the route to the
        objective (confirmed hops + candidate transitions, impact phases flagged
        gated). It executes nothing; post-exploitation is human-gated and
        operator-driven.
        """

        from .killchain.plan import KillChainPlanner

        return KillChainPlanner(self.store).plan(goal_host, goal_privilege)

    def post_ex(self, backend: C2Backend) -> PostExOperator:
        """Post-exploitation operator (O3) over this engagement's C2 sessions.

        Authorized (engagement-boundary or gated), scope-bound to session hosts,
        kill-switchable, audited — operates the footholds exploitation established.
        """

        from .c2.postex import PostExOperator

        return PostExOperator(
            self.session_manager, backend, self.scope, self.audit,
            gate=self.context.gate, kill_switch=self.kill_switch,
        )

    def foothold(self, backend: C2Backend) -> FootholdRunner:
        """Foothold runner (O2→O3) over this engagement's C2 backend.

        Establishes and *proves* live sessions from a landed exploit — authorized
        (engagement-boundary or gated), scope-bound, kill-switchable, audited. Its
        ``teardown()`` closes both the session bookkeeping and the transport, so a
        kill-switch trip releases live footholds, not just refuses new ones.
        """

        from .c2.foothold import FootholdRunner

        return FootholdRunner(
            self.session_manager, backend, self.scope, self.audit,
            gate=self.context.gate, kill_switch=self.kill_switch,
        )

    def lateral(
        self, client: LateralClient, vault: CredentialVault
    ) -> LateralMovementLauncher:
        """Lateral-movement launcher (E4) — reuse an owned credential to land a
        proven session on a new host via PtH / PtT / valid accounts.

        Wires a governed :class:`~attack_engine.c2.foothold.FootholdRunner` over a
        :class:`~attack_engine.c2.lateral.LateralBackend`, so the credential-reuse
        foothold is authorized (technique-tagged), scope-bound, kill-switchable,
        and audited exactly like any other. ``vault`` is the credential vault the
        secret material is read from at the moment of use (never audited).
        """

        from .c2.lateral import LateralBackend, LateralMovementLauncher

        runner = self.foothold(LateralBackend(client))
        return LateralMovementLauncher(runner, client, vault)

    def orchestrator(self, *, blue_sentry: BlueSentry | None = None) -> Orchestrator:
        """Build an Orchestrator bound to this engagement (drives the full loop)."""

        from .orchestrator.orchestrator import Orchestrator

        return Orchestrator(self, blue_sentry=blue_sentry)



class Engine:
    """Process-wide services, constructed once from settings."""

    def __init__(
        self,
        settings: Settings,
        *,
        audit: AuditLog,
        event_bus: EventBus,
        gateway: ModelGateway,
        sandbox: Sandbox,
        registry: ToolRegistry,
        feed: CveFeed | None = None,
        scorer: ExploitabilityScorer | None = None,
        gate_responder: Responder | None = None,
    ) -> None:
        self.settings = settings
        self.audit = audit
        self.event_bus = event_bus
        self.gateway = gateway
        self.sandbox = sandbox
        self.registry = registry
        self.feed = feed or build_cve_feed(settings)
        self.calibrator = build_calibrator(settings)
        self.scorer = scorer or ExploitabilityScorer(calibrator=self.calibrator)
        # Fail closed: with no responder wired, every gated action is denied.
        self.gate_responder = gate_responder or deny_all

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Engine:
        s = settings or get_settings()
        configure_logging(level=s.log_level, json_output=s.log_json)
        audit = AuditLog(build_audit_backend(s))
        event_bus = build_event_bus(s)
        gateway = ModelGateway(settings=s, audit=audit)
        sandbox = build_sandbox(s)
        registry = default_registry()
        _log.info(
            "engine initialised",
            audit=s.audit_backend.value,
            eventbus=s.eventbus_backend.value,
            sandbox=sandbox.name,
            model_provider=gateway.provider_name,
        )
        return cls(
            s,
            audit=audit,
            event_bus=event_bus,
            gateway=gateway,
            sandbox=sandbox,
            registry=registry,
        )

    def blue_sentry(self, scope: Scope) -> BlueSentry:
        """Build a Blue Sentry for an engagement (attach it before the loop runs)."""

        return BlueSentry(scope, self.audit)

    def _build_graph(self, scope: Scope) -> GraphBackend:
        """Per-engagement graph backend (NetworkX default; Neo4j scoped by id)."""

        from .config import GraphBackendKind
        from .knowledge.graph import AttackGraph

        if self.settings.graph_backend is GraphBackendKind.NETWORKX:
            return AttackGraph()
        from .knowledge.neo4j_backend import Neo4jGraphBackend

        s = self.settings
        return Neo4jGraphBackend(
            url=s.neo4j_url,
            user=s.neo4j_user,
            password=s.neo4j_password.get_secret_value() if s.neo4j_password else None,
            engagement_id=scope.engagement_id,
            database=s.neo4j_database,
        )

    def engagement(
        self,
        scope: Scope,
        *,
        require_signed: bool | None = None,
        gate_responder: Responder | None = None,
    ) -> Engagement:
        """Bind services to a signed scope. Refuses unsigned scopes in prod.

        ``gate_responder`` overrides the engine default for this engagement only
        — the EngagementManager uses it to wire an RBAC-authorised approver.
        """

        must_sign = self.settings.is_prod() if require_signed is None else require_signed
        if must_sign and not scope.is_signed():
            raise AttackEngineError(
                f"scope {scope.engagement_id!r} is not signed; refusing to run"
            )
        if scope.is_expired():
            raise AttackEngineError(f"scope {scope.engagement_id!r} has expired")

        store = KnowledgeStore(
            scope.engagement_id, event_bus=self.event_bus, graph=self._build_graph(scope)
        )
        network = self.settings.sandbox_network or f"ae-{scope.engagement_id}"
        runner = ToolRunner(
            scope,
            registry=self.registry,
            audit=self.audit,
            sandbox=self.sandbox,
            event_bus=self.event_bus,
            network=network,
        )
        gate = HumanGate(self.audit, responder=gate_responder or self.gate_responder)
        kill_switch = KillSwitch()
        session_manager = SessionManager(scope, self.audit)
        ctx = AgentContext(
            scope=scope,
            tool_runner=runner,
            store=store,
            audit=self.audit,
            gateway=self.gateway,
            event_bus=self.event_bus,
            gate=gate,
            kill_switch=kill_switch,
        )
        # Record engagement start in the immutable log.
        self.audit.append(
            engagement_id=scope.engagement_id,
            actor="engine",
            action="engagement.start",
            payload={
                "authorized_by": scope.authorized_by,
                "cidrs": list(scope.allowed_cidrs),
                "hosts": list(scope.allowed_hosts),
                "read_only": scope.roe.read_only,
            },
        )
        return Engagement(
            scope=scope,
            store=store,
            tool_runner=runner,
            context=ctx,
            registry=self.registry,
            audit=self.audit,
            feed=self.feed,
            scorer=self.scorer,
            session_manager=session_manager,
            kill_switch=kill_switch,
            calibrator=self.calibrator,
        )
