"""The engine adapter — the seam between the HTTP shell and the real engine.

One :class:`EngineAdapter` wraps a single process-wide
:class:`~attack_engine.engine.Engine` and its multi-tenant
:class:`~attack_engine.manager.EngagementManager`. It:

* maps the console's Rules-of-Engagement document onto a signed engine
  :class:`~attack_engine.schemas.scope.Scope`;
* opens / halts / resumes / closes live engagements;
* drives the real recon / verify / correlate stages;
* reads assets, findings and the hash-chained audit log back out as the JSON
  shapes the console expects (via :mod:`attack_engine.api.serialize`).

Security is *not* re-implemented here. Scope enforcement, gates, the kill
switch and the audit chain all live in the engine; this class only exposes
them. Engagement *handles* are held by a trusted internal service principal
(the API process is a trusted component); per-user authorization — which role
may hit which route, and gate-approver identity — is enforced by the HTTP layer
that calls this adapter.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import queue
import re
import threading
import time
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Any

from ..agents.loader import build_agent, load_spec
from ..config import Settings
from ..correlate.matcher import MatchReport
from ..engine import Engagement, Engine
from ..errors import AttackEngineError, AuditIntegrityError
from ..governance.rbac import AccessControl, Principal, Role
from ..manager import EngagementManager
from ..schemas.common import utcnow
from ..schemas.events import Event
from ..schemas.findings import FindingState
from ..schemas.scope import RateLimit, RulesOfEngagement, Scope
from ..verify.verifier import VerifyReport
from . import views
from .approvals import ApprovalBroker
from .serialize import asset_to_json, audit_entry_to_json, finding_to_json

_SPECS_DIR = Path(__file__).resolve().parent.parent / "agents" / "specs"

#: console max_intensity → (read_only, autonomy_tier). recon and safe-active
#: stay read-only (no mutating tool may launch); exploit lifts read-only so the
#: gated confirmation modules can run. Autonomy tier ≥1 lets the signed scope
#: pre-authorize the safe portion of the loop; high-impact actions still gate.
_INTENSITY: dict[str, tuple[bool, int]] = {
    "recon": (True, 0),
    "safe-active": (True, 1),
    "exploit": (False, 1),
}

_ID_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


def engagement_id_for(external_id: str) -> str:
    """Derive an engine-valid engagement id from any external id.

    The engine requires ``^eng(agement)?-[A-Za-z0-9_-]+$``; console ids (uuids,
    slugs) are sanitized and prefixed so the two systems share one id space.
    """

    slug = _ID_SAFE.sub("-", (external_id or "").strip()).strip("-")
    if not slug:
        slug = "unknown"
    return slug if slug.startswith(("eng-", "engagement-")) else f"eng-{slug}"


def principal_from(
    role: str, user_id: str, engagements: list[str] | None = None
) -> Principal:
    """Map a console user (role string + id) onto an engine :class:`Principal`.

    ``engagements`` scopes the principal to specific engagement ids (multi-tenant
    isolation); empty/None ⇒ all (admins and services).
    """

    try:
        engine_role = Role(role)
    except ValueError:
        engine_role = Role.VIEWER
    return Principal(
        id=user_id,
        roles=frozenset({engine_role}),
        engagements=frozenset(engagement_id_for(e) for e in (engagements or [])),
    )


def _classify_target(entry: str) -> tuple[str, str] | None:
    """Classify one allowlist entry as ('cidr', net) or ('host', name).

    Accepts CIDRs, bare IPs (→ /32 or /128 CIDR), hostnames, ``host:port`` and
    full URLs (scheme + path stripped). Returns None for unusable entries.
    """

    entry = (entry or "").strip()
    if not entry:
        return None
    # A real CIDR (has a prefix length) — keep as-is.
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ("cidr", str(net))
        except ValueError:
            pass  # not a CIDR — probably a URL with a path; fall through
    host = entry
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]  # drop any path
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # drop :port
    host = host.strip("[]")  # bracketed IPv6
    try:
        ip = ipaddress.ip_address(host)
        prefix = 32 if ip.version == 4 else 128
        return ("cidr", str(ipaddress.ip_network(f"{host}/{prefix}", strict=False)))
    except ValueError:
        return ("host", host.lower())


def scope_from_roe(
    external_id: str,
    roe: dict[str, Any],
    *,
    authorized_by: str | None = None,
    signature: str | None = None,
) -> Scope:
    """Build a signed engine :class:`Scope` from a console RoE document.

    ``roe`` uses the console's field names (``scope_allowlist``,
    ``allowed_techniques``, ``max_intensity``, ``window_end`` …). Allowlist
    entries are split into CIDRs and hostnames; ``max_intensity`` sets the
    read-only master switch and autonomy tier; ``window_end`` becomes the scope
    expiry; ``signature``/``authorized_by`` bind the human authorization.
    """

    def _split_targets(entries: list[str]) -> tuple[list[str], list[str]]:
        cidrs: list[str] = []
        hosts: list[str] = []
        for entry in entries or []:
            classified = _classify_target(entry)
            if classified is None:
                continue
            kind, value = classified
            (cidrs if kind == "cidr" else hosts).append(value)
        return cidrs, hosts

    cidrs, hosts = _split_targets(roe.get("scope_allowlist") or [])
    denied_cidrs, denied_hosts = _split_targets(roe.get("scope_denylist") or [])

    intensity = str(roe.get("max_intensity") or "recon")
    read_only, tier = _INTENSITY.get(intensity, (True, 0))

    techniques = set(roe.get("allowed_techniques") or [])
    if intensity == "exploit":
        techniques |= {"exploit_confirm", "exploitation"}

    def _parse_dt(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None

    expires_at = _parse_dt(roe.get("window_end"))
    starts_at = _parse_dt(roe.get("window_start"))

    rules = RulesOfEngagement(
        read_only=read_only,
        autonomy_tier=tier,
        authorized_techniques=frozenset(techniques),
        forbidden_tools=frozenset(roe.get("forbidden_tools") or []),
        # The console's "Allowed Tools" picker — empty means no restriction.
        allowed_tools=frozenset(roe.get("allowed_tools") or []),
        # Headroom for the verification oracles' rapid differential probing
        # (boolean-blind SQLi fires several http_probes back-to-back).
        default_rate_limit=RateLimit(requests_per_sec=50, burst=20),
    )
    return Scope(
        engagement_id=engagement_id_for(external_id),
        allowed_cidrs=tuple(dict.fromkeys(cidrs)),
        allowed_hosts=tuple(dict.fromkeys(hosts)),
        denied_cidrs=tuple(dict.fromkeys(denied_cidrs)),
        denied_hosts=tuple(dict.fromkeys(denied_hosts)),
        roe=rules,
        authorized_by=authorized_by,
        signature=signature,
        starts_at=starts_at,
        expires_at=expires_at,
    )


class EngineAdapter:
    """Holds the engine + manager and bridges console operations to it."""

    #: trusted internal identity that holds engagement handles on the service's
    #: behalf; per-user authorization is enforced by the HTTP layer above.
    _SERVICE_ID = "engine-api-service"

    def __init__(
        self,
        engine: Engine | None = None,
        *,
        settings: Settings | None = None,
        access: AccessControl | None = None,
    ) -> None:
        self._engine = engine or Engine.from_settings(settings)
        self._manager = EngagementManager(self._engine, access=access)
        self._service = Principal(id=self._SERVICE_ID, roles=frozenset({Role.ADMIN}))
        #: signed scopes we've opened, keyed by engine engagement id.
        self._scopes: dict[str, Scope] = {}
        #: agent-run summaries per engine engagement id (for the Console tab).
        self._runs: dict[str, list[dict[str, Any]]] = {}
        #: background job history + a per-engagement "busy" lock, so long,
        #: Docker-spawning operations (recon/vuln-scan) run off the request
        #: thread and the HTTP call returns immediately.
        self._jobs: dict[str, list[dict[str, Any]]] = {}
        self._busy: set[str] = set()
        self._job_lock = threading.Lock()
        #: per-engagement event queues fed from the engine event bus → SSE.
        self._events: dict[str, queue.Queue[dict[str, Any]]] = {}
        #: async human-approval broker — parks gated actions for the console.
        self._approvals = ApprovalBroker()
        #: latest re-test result per finding (engine eid → finding id → row).
        self._retests: dict[str, dict[str, dict[str, Any]]] = {}
        #: saved Red Scope copilot presets (session-scoped).
        self._red_scope_agents: list[dict[str, Any]] = []
        #: live campaign phase per engine engagement id (for the kill-chain progress
        #: bar): the phase currently executing, or None when idle.
        self._campaign_stage: dict[str, str | None] = {}
        #: established C2 footholds per engine eid → session id → operating context
        #: (backend + foothold runner + post-ex operator + proof), so the console can
        #: list live sessions, run post-ex, and tear them down.
        self._footholds: dict[str, dict[str, dict[str, Any]]] = {}
        bus = self._engine.event_bus
        if hasattr(bus, "subscribe"):
            bus.subscribe(self._route_event)

    # ── accessors ─────────────────────────────────────────────────────────
    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def manager(self) -> EngagementManager:
        return self._manager

    def is_open(self, external_id: str) -> bool:
        return engagement_id_for(external_id) in self._manager.list_open(self._service)

    def engagement(self, external_id: str) -> Engagement:
        """Return the live engine engagement handle (service principal)."""

        return self._manager.get(engagement_id_for(external_id), self._service)

    # ── lifecycle ─────────────────────────────────────────────────────────
    def open(self, scope: Scope, *, require_signed: bool | None = None) -> Engagement:
        """Bind a signed scope → live engagement (idempotent per id).

        For a real signed scope, gated (high-impact) actions are routed to the
        :class:`ApprovalBroker` so a human approves/denies them from the console.
        A one-click *test* scope keeps the engine's frictionless auto-approve
        (the operator already opted in via ``AE_ALLOW_TEST_AUTH``).
        """

        responder = None if scope.is_test_authorization else self._approvals.responder
        eng = self._manager.open(
            scope, self._service,
            gate_responder=responder, require_signed=require_signed,
        )
        self._scopes[scope.engagement_id] = scope
        # Rehydrate the Console's agent-run history from the durable backend (the
        # engagement store itself rehydrates its assets/findings in KnowledgeStore).
        backend = self._engine.knowledge_backend
        if backend is not None and scope.engagement_id not in self._runs:
            with contextlib.suppress(Exception):
                runs = backend.load_agent_runs(scope.engagement_id)
                if runs:
                    self._runs[scope.engagement_id] = runs
        return eng

    def open_for_testing(
        self, external_id: str, targets: list[str], *, autonomy_tier: int = 2
    ) -> Engagement:
        """One-click **test** engagement from the console — no signing overhead.

        Builds a :meth:`Scope.for_testing` scope for ``targets`` and opens it. The
        engine still refuses this unless the deployment set ``AE_ALLOW_TEST_AUTH``
        (checked in :meth:`Engine.engagement`), so this is a testing-deployment
        convenience, never a way around real authorization.
        """

        scope = Scope.for_testing(
            targets,
            engagement_id=engagement_id_for(external_id),
            autonomy_tier=autonomy_tier,
        )
        return self.open(scope)

    def halt(
        self, external_id: str, *, by: str = "operator", reason: str = "operator halt"
    ) -> None:
        """Trip the engagement kill switch (real halt, checked before each action)."""

        self.engagement(external_id).kill_switch.trip(reason=reason, by=by)

    def is_halted(self, external_id: str) -> bool:
        return self.engagement(external_id).kill_switch.tripped

    def resume(self, external_id: str) -> Engagement:
        """Re-bind a fresh engagement handle after a hard halt.

        A tripped :class:`KillSwitch` is a permanent stop for its engagement (by
        design — a kill switch you can silently un-trip is not a kill switch), so
        resuming means re-opening the *same signed scope* on a fresh handle. The
        blackboard starts clean; re-running recon repopulates it.
        """

        eid = engagement_id_for(external_id)
        scope = self._scopes.get(eid)
        if scope is None:
            raise KeyError(f"no scope on record for {eid!r}; cannot resume")
        with contextlib.suppress(AttackEngineError):
            self._manager.close(eid, self._service)
        return self.open(scope)

    def close(self, external_id: str) -> None:
        eid = engagement_id_for(external_id)
        self._manager.close(eid, self._service)
        self._scopes.pop(eid, None)

    def _forget_runtime(self, eid: str) -> None:
        """Drop all in-process runtime state for an engagement id."""

        for d in (self._runs, self._footholds, self._jobs, self._events,
                  self._retests, self._scopes):
            d.pop(eid, None)
        self._campaign_stage.pop(eid, None)
        self._busy.discard(eid)

    def purge_engagement(self, external_id: str, *, actor: str = "operator") -> dict[str, Any]:
        """Wipe an engagement's RESULTS (assets/findings/remediations/tool-runs/agent-
        runs) — durable + in-memory — but keep the engagement, its RoE, and the
        immutable audit chain. The operator's "clear results / start fresh" control.
        """

        eid = engagement_id_for(external_id)
        backend = self._engine.knowledge_backend
        if backend is not None:
            with contextlib.suppress(Exception):
                backend.delete(eid)
        self._runs.pop(eid, None)
        self._footholds.pop(eid, None)
        self._retests.pop(eid, None)
        # re-open on a clean store so the live handle reflects the purge immediately
        scope = self._scopes.get(eid)
        if scope is not None:
            with contextlib.suppress(AttackEngineError):
                self._manager.close(eid, self._service)
            self.open(scope)
        self.record_governance(eid, actor=actor, action="engagement.purged",
                               target=eid, payload={"scope": "results"})
        return {"ok": True, "purged": "results"}

    def delete_engagement(self, external_id: str, *, actor: str = "operator") -> dict[str, Any]:
        """Delete an engagement entirely: close the live handle, wipe its persisted
        results, and drop all runtime state. Records ``engagement.deleted`` on the
        (immutable) audit chain first — deletion never touches the audit log itself.
        The API removes the shell metadata doc.
        """

        eid = engagement_id_for(external_id)
        with contextlib.suppress(Exception):
            self.record_governance(eid, actor=actor, action="engagement.deleted",
                                   target=eid, payload={})
        backend = self._engine.knowledge_backend
        if backend is not None:
            with contextlib.suppress(Exception):
                backend.delete(eid)
        with contextlib.suppress(AttackEngineError):
            self._manager.close(eid, self._service)
        self._forget_runtime(eid)
        return {"ok": True, "deleted": eid}

    # ── operations (real engine work) ──────────────────────────────────────
    def _persist_run(self, eid: str, run: dict[str, Any]) -> None:
        """Record an agent/campaign run summary + persist it so the Console's Agent
        Runs list survives an API restart (rehydrated on engagement re-open)."""

        self._runs.setdefault(eid, []).append(run)
        backend = self._engine.knowledge_backend
        if backend is not None:
            with contextlib.suppress(Exception):
                backend.save_agent_run(eid, run)

    def _record_run(self, eid: str, report: Any, *, name: str, role: str) -> None:
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": name, "role": role, "status": "completed",
            "detection_rate": None, "started_at": utcnow().isoformat(),
            "ended_at": utcnow().isoformat(),
            "summary": (
                f"{report.tool_calls} tool calls · {report.assets_found} assets · "
                f"{report.findings_proposed} findings proposed"
            ),
            "steps": [], "detections": [], "approvals_created": 0,
        })

    def sense(self, external_id: str, targets: list[str]) -> Any:
        """Run the Surface Mapper recon archetype over ``targets``."""

        eng = self.engagement(external_id)
        spec = load_spec(_SPECS_DIR / "surface_mapper.yaml")
        report = eng.run_agent(spec, list(targets))
        self._record_run(engagement_id_for(external_id), report,
                         name="Surface Mapper", role="recon")
        return report

    def _record_loop_run(
        self, eid: str, *, name: str, role: str, result: Any, extra: str = ""
    ) -> None:
        """Record a reasoning-loop / campaign run for the Console's Agent Runs panel."""

        iters = getattr(result, "iterations", 0)
        stop = getattr(result, "stop_reason", "")
        met = getattr(result, "objective_met", None)
        summary = f"{iters} reasoning steps · stop={stop}"
        if met is not None:
            summary += f" · objective_met={met}"
        if extra:
            summary += f" · {extra}"
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": name, "role": role, "status": "completed",
            "detection_rate": None, "started_at": utcnow().isoformat(),
            "ended_at": utcnow().isoformat(), "summary": summary,
            "steps": [], "detections": [], "approvals_created": 0,
        })

    def _web_targets_or_recon(self, external_id: str) -> list[str]:
        """Web surfaces to sweep — self-sufficient.

        Returns the web services recon already classified; if there are none yet
        (the deployed operator ran Vuln Scan / Run Full Attack without a prior Sense,
        or recon under-classified the port), it runs recon on the authorized scope
        targets first so a web surface is discovered. This is why the pipeline finds
        + confirms vulns in the deployed console, not just after a manual Sense.
        """

        from ..netutil import web_targets

        eng = self.engagement(external_id)
        web = web_targets(eng.store)
        if web:
            return web
        targets = self._scope_targets(external_id)
        if not targets:
            return []
        eid = engagement_id_for(external_id)
        self._emit(eid, "sweep.recon", {"reason": "no web service yet", "targets": targets})
        with contextlib.suppress(Exception):
            self.sense(external_id, targets)
        return web_targets(eng.store)

    def _deterministic_web_sweep(self, external_id: str, targets: list[str]) -> int:
        """Exhaustive, LLM-independent web discovery — the reliable finding engine.

        Crawls every web target (katana) + broad-scans it (nuclei), then probes the
        discovered parameters for reflected-XSS (dalfox) and SQLi (sqlmap), folding
        it all into the world model and graduating EVERY oracle-ready candidate into
        a PROPOSED finding. The deterministic oracles (:meth:`Engagement.verify`) then
        confirm what's real. Unlike the model-driven loop this always runs the same
        thorough sweep, so findings don't depend on the planner's choices — the fix
        for "runs but finds nothing". Every tool call is scope-checked + degrades on
        its own, and streams a ``sweep.*`` event so the console shows each step.
        Returns the number of PROPOSED findings graduated.
        """

        from urllib.parse import urlsplit

        from ..agents.actions import ProposedAction
        from ..agents.payload_synth import PayloadSynthesizer
        from ..agents.reasoning import LoopContext
        from ..agents.tool_actor import ToolRunnerActor
        from ..agents.web_specialist import WebGraduator, WebObserver

        eng = self.engagement(external_id)
        eid = engagement_id_for(external_id)
        wm = eng.world_model
        if wm is None:
            return 0
        actor = ToolRunnerActor(eng.tool_runner)
        observer = WebObserver()
        ctx = LoopContext(wm, "exhaustive web discovery", (), 0, None)

        def run(tool: str, target: str, params: dict[str, Any] | None = None) -> None:
            try:
                action = ProposedAction(
                    tool=tool, target=target, params=params or {},
                    rationale="deterministic thorough sweep", expected_value=0.9,
                )
                outcome = actor.act(action)
                observer.observe(action, outcome, ctx)
                self._emit(eid, "sweep.tool",
                           {"tool": tool, "target": target, "ok": bool(outcome.ok)})
            except Exception as exc:  # never let one tool sink the sweep
                self._emit(eid, "sweep.error",
                           {"tool": tool, "detail": f"{type(exc).__name__}: {exc}"})

        # 1. crawl every surface (→ every parameter becomes an injection candidate)
        #    and broad-scan it (→ CVE / misconfig / exposure findings). Katana's
        #    parameters cover the injection classes; the oracles in verify() then
        #    confirm each class deterministically — so this pair + the oracle suite
        #    is exhaustive without a slow per-parameter scanner sweep.
        for url in targets:
            parts = urlsplit(url if "://" in url else f"http://{url}")
            host = parts.hostname or url
            scheme = parts.scheme or "http"
            port = parts.port
            base = {"scheme": scheme, **({"port": port} if port else {})}
            run("katana", host, base)
            run("nuclei", host, base)

        # 2. graduate EVERY oracle-ready candidate → PROPOSED (verify confirms next)
        synth = (PayloadSynthesizer(eng.context.gateway, engagement_id=eid)
                 if eng.context.gateway is not None else None)
        graduated = WebGraduator(eng.store, synthesizer=synth).graduate(wm)
        self._emit(eid, "sweep.graduated", {"count": len(graduated)})
        return len(graduated)

    #: High-signal ports the network-exploit path scans explicitly. nmap's
    #: top-1000 default misses several classically-exploitable services (distcc
    #: 3632, r-services, ingreslock, drb…) and masscan may be unavailable, so the
    #: exploitation feed scans this curated set to reliably surface a foothold
    #: service. These are the ports behind the ``metasploit`` exploit catalog plus
    #: the well-known vulnerable services on a red-team range.
    _EXPLOIT_SCAN_PORTS = (
        "21,22,23,25,111,139,445,512,513,514,1099,1524,2049,3306,3632,"
        "5432,5900,6000,6667,6697,8009,8180,8787,50000"
    )

    def _scan_exploit_ports(self, external_id: str) -> int:
        """nmap the curated exploitable-service ports and ingest exposed services.

        Reliable, self-contained service discovery for the exploitation feed — does
        not slow the general recon default. Returns the number of open services
        folded onto the target assets (as PROPOSED ``exposed-service`` findings the
        Metasploit module can match). Every scan is scope-enforced + audited.
        """

        from ..schemas.findings import Asset, Finding, Priority, Service
        from ..schemas.tools import ToolProfile

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        targets = self._scope_targets(external_id)
        found = 0
        for target in targets:
            profile = ToolProfile(preset="default", args={"ports": self._EXPLOIT_SCAN_PORTS})
            try:
                result = eng.tool_runner.run("nmap", target, profile)
            except Exception as exc:  # out-of-scope / degraded — skip this target
                self._emit(eid, "exploit.scan_error",
                           {"target": target, "detail": f"{type(exc).__name__}: {exc}"})
                continue
            open_ports = result.parsed.get("ports", [])
            if not open_ports:
                continue
            services = tuple(
                Service(port=int(p["port"]), protocol=p.get("protocol", "tcp"),
                        name=p.get("service"), product=p.get("product"),
                        version=p.get("version"))
                for p in open_ports
            )
            with contextlib.suppress(Exception):
                eng.store.add_asset(
                    Asset(address=target, services=services,
                          engagement_id=eng.scope.engagement_id),
                    emitted_by="exploit.scan",
                )
            for svc in services:
                finding = Finding(
                    engagement_id=eng.scope.engagement_id, asset=target,
                    service=svc.cpe_hint, type=f"exposed-service:{svc.port}/{svc.protocol}",
                    title=f"Exposed {svc.name or 'service'} on {target}:{svc.port}",
                    priority=Priority.INFORMATIONAL, evidence=(f"raw:{result.audit_id}",),
                    proposed_by="exploit.scan",
                    metadata={"port": svc.port, "product": svc.product, "version": svc.version},
                )
                with contextlib.suppress(Exception):
                    eng.store.propose_finding(finding, emitted_by="exploit.scan")
                    found += 1
        self._emit(eid, "exploit.scan", {"services": found})
        return found

    def _exploit_network_services(self, external_id: str) -> int:
        """Real, gated exploitation of recon'd network services — the *non-web*
        foothold path (nmap vuln service → Metasploit module → live session →
        CONFIRMED RCE), complementing the web cmdi→C2 path so Full Attack reaches a
        foothold from either surface.

        Runs the confirmation-grade exploit modules over any PROPOSED exposed-
        service/CVE finding they handle. First scans the curated exploitable-service
        ports (:meth:`_scan_exploit_ports`) so a foothold service on a non-standard
        port (e.g. distcc 3632) is actually found — the default recon's top-1000
        misses these and masscan may be unavailable. Fully governed: the
        ``exploit_confirm`` gate decides autonomous (signed scope, Tier ≥ 1) vs
        human, every run is scope-enforced + audited, and it degrades on its own.
        Returns confirmations.
        """

        from ..governance.authorization import AuthorizationDecision, AuthorizationPolicy

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        # Only drive REAL exploitation autonomously when the signed scope
        # pre-authorizes exploit_confirm (Tier ≥ 1). Otherwise skip — an
        # unattended campaign must never block on a human gate, and exploitation
        # off the authorization allowlist is the operator's explicit call (from
        # the console, where the approvals UI resolves the gate). Fail-safe.
        if AuthorizationPolicy(eng.scope).decide("exploit_confirm") is not (
            AuthorizationDecision.AUTONOMOUS
        ):
            self._emit(eid, "exploit.skipped",
                       {"reason": "exploit_confirm not pre-authorized (gate required)"})
            return 0
        with contextlib.suppress(Exception):
            self._scan_exploit_ports(external_id)
        try:
            report = eng.exploit()
        except AttackEngineError as exc:  # gate not wired / RoE — degrade, don't sink
            self._emit(eid, "exploit.degraded",
                       {"detail": f"{type(exc).__name__}: {exc}"})
            return 0
        self._emit(eid, "exploit.done", {
            "confirmed": report.confirmed, "disproven": report.disproven,
            "gate_denied": report.gate_denied,
        })
        return report.confirmed

    def _autolaunch_footholds(self, external_id: str, *, limit: int = 3) -> list[str]:
        """Execute the composed chains: land live C2 footholds on confirmed points.

        The autonomous half of "compose chains → *reach* a foothold" (pilot #2). Once
        the sweep/exploit have produced CONFIRMED command-execution findings, open a
        real governed session on each (bounded by ``limit``, one per host) so Full
        Attack actually establishes the foothold instead of only composing the route
        to it. Only runs when the signed scope pre-authorizes ``establish_foothold``
        (Tier ≥ 1) — it never blocks an unattended campaign on a human gate. Returns
        the ids of the sessions opened.
        """

        from ..governance.authorization import AuthorizationDecision, AuthorizationPolicy

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        if AuthorizationPolicy(eng.scope).decide("establish_foothold") is not (
            AuthorizationDecision.AUTONOMOUS
        ):
            self._emit(eid, "foothold.skipped",
                       {"reason": "establish_foothold not pre-authorized (gate required)"})
            return []
        opened: list[str] = []
        seated = {c.get("host") for c in self._footholds.get(eid, {}).values()}
        for f in eng.store.findings(FindingState.CONFIRMED):
            if len(opened) >= limit:
                break
            if not self._is_foothold_capable(f) or f.asset in seated:
                continue
            try:
                session = self.establish_foothold(external_id, f.id, actor="campaign")
            except AttackEngineError:
                continue  # gate/liveness failed — try the next candidate
            if session:
                opened.append(session["id"])
                seated.add(f.asset)
        self._emit(eid, "foothold.autolaunched", {"sessions": opened})
        return opened

    def _run_web_loop(self, external_id: str, *, max_steps: int = 14) -> Any:
        """Drive the REAL Web specialist reasoning loop over the engagement.

        The loop plans web probes through the model gateway, acts through the
        scope-enforcing Tool Runner, and graduates oracle-ready beliefs into
        PROPOSED findings (the Phase-D "web recon → proof" seam) against the
        engagement's registered world model. Best-effort: any loop error degrades
        to the deterministic verify/correlate gate — it never sinks the scan.
        """

        from ..agents.web_specialist import build_web_loop
        from ..orchestrator.controller import ObjectiveController
        from ..orchestrator.objective import ConfidenceObjective

        eng = self.engagement(external_id)
        eid = engagement_id_for(external_id)
        wm = eng.world_model
        if wm is None:  # every engagement registers one in __post_init__
            return None
        try:
            loop = build_web_loop(eng.context, max_steps=max_steps)
            result = ObjectiveController(loop).pursue(
                wm, ConfidenceObjective(kind="vulnerability", threshold=0.85),
            )
            self._record_loop_run(eid, name="Web Inquisitor", role="offensive", result=result)
            return result
        except Exception as exc:  # degrade — the oracles below are the real gate
            self._emit(eid, "loop.degraded",
                       {"loop": "web", "detail": f"{type(exc).__name__}: {exc}"})
            return None

    def _compose_chains(self, eng: Engagement) -> None:
        """Compose + refresh attack chains from the world model's beliefs and the
        CONFIRMED findings, so the attack-path view renders the REAL chained kill
        routes (e.g. cmdi→foothold, lfi→source→creds, open-redirect→ssrf→metadata→
        creds→foothold) rather than a flat finding list. Best-effort."""

        wm = eng.world_model
        if wm is None:
            return
        with contextlib.suppress(Exception):
            from ..agents.web_chain import WebChainer

            WebChainer().compose(wm)

    # ── offensive C2 / footholds (real live sessions) ──────────────────────
    #: Confirmed finding types that are a command-execution foothold point.
    _FOOTHOLD_TYPES = ("command-injection", "cmdi", "os-command", "rce")

    def _is_foothold_capable(self, finding: Any) -> bool:
        """A CONFIRMED command-execution finding with a usable injection point."""

        ft = (getattr(finding, "type", "") or "").lower()
        return (
            finding.state == FindingState.CONFIRMED
            and any(ft.startswith(p) for p in self._FOOTHOLD_TYPES)
            and bool((finding.metadata or {}).get("param"))
        )

    def foothold_candidates(self, external_id: str) -> list[dict[str, Any]]:
        """Confirmed command-execution findings a live foothold can be opened on."""

        if not self.is_open(external_id):
            return []
        eng = self.engagement(external_id)
        out: list[dict[str, Any]] = []
        for f in eng.store.findings(FindingState.CONFIRMED):
            if self._is_foothold_capable(f):
                out.append({"finding_id": f.id, "title": f.title or f.type,
                            "host": f.asset, "param": (f.metadata or {}).get("param"),
                            "type": f.type})
        return out

    def establish_foothold(self, external_id: str, finding_id: str,
                           *, actor: str = "operator") -> dict[str, Any]:
        """Open + PROVE a live, governed C2 session over a confirmed web RCE.

        Builds a web-shell C2 backend from the confirmed command-injection point and
        drives the real :class:`FootholdRunner` (authorize → open scope-checked
        session → prove whoami/id/hostname → track). Governed: the establish action
        is gated (auto-approved under test auth, human-approved under a real scope),
        audited, and kill-switchable. Runs on a worker (see the ``foothold`` job kind)
        because the gate blocks the caller until a human resolves it.
        """

        from ..c2.webshell import web_shell_backend

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        finding = eng.store.get_finding(finding_id)
        if finding is None:
            raise AttackEngineError(f"finding {finding_id!r} not found")
        if not self._is_foothold_capable(finding):
            raise AttackEngineError(
                "finding is not a confirmed command-execution point — a live foothold "
                "needs a CONFIRMED command-injection/RCE finding with an injection param"
            )
        backend = web_shell_backend(eng.tool_runner, finding)
        runner = eng.foothold(backend)
        self._emit(eid, "c2.establishing", {"finding": finding_id, "host": finding.asset})
        foothold = runner.establish(
            finding.asset, opened_by=actor, technique="T1190",
            metadata={"finding": finding_id},
        )
        if foothold is None:
            raise AttackEngineError("foothold denied by the approval gate")
        if not foothold.ok:
            raise AttackEngineError("session opened but liveness/proof failed")
        sess = foothold.session
        self._footholds.setdefault(eid, {})[sess.id] = {
            "backend": backend, "runner": runner, "postex": eng.post_ex(backend),
            "proof": dict(foothold.proof), "technique": "T1190",
            "host": finding.asset, "finding_id": finding_id,
            "opened_at": utcnow().isoformat(),
        }
        self._emit(eid, "c2.foothold", {"session": sess.id, "host": finding.asset,
                                        "whoami": foothold.proof.get("whoami", "?")})
        # Proof-of-impact showcase: auto-run bounded loot over the fresh session
        # and capture the served site content — the concrete "here is what we
        # achieved" evidence surfaced in the console's Footholds & C2 panel.
        with contextlib.suppress(Exception):
            self._capture_proof_of_impact(external_id, sess.id, finding)
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": "Foothold", "role": "offensive", "status": "completed",
            "detection_rate": None, "started_at": utcnow().isoformat(),
            "ended_at": utcnow().isoformat(),
            "summary": (f"live session on {finding.asset} — "
                        f"whoami={foothold.proof.get('whoami', '?')} "
                        f"host={foothold.proof.get('hostname', '?')}"),
            "steps": [], "detections": [], "approvals_created": 0,
        })
        return self._session_json(eid, sess.id)

    #: Bounded, benign loot commands auto-run on a fresh foothold to demonstrate
    #: the access we proved — identity + host + reachability. Read-only; reveals
    #: only the host's own identity, never target data. This is the auto-run
    #: half of the proof-of-impact showcase.
    _LOOT_COMMANDS: tuple[str, ...] = (
        "id", "whoami", "hostname", "uname -a",
        "ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null",
    )

    def _capture_proof_of_impact(self, external_id: str, session_id: str,
                                 finding: Any) -> None:
        """Auto-run loot + capture served site content on a fresh foothold.

        The concrete "here is what we achieved" evidence for the console: a
        bounded loot command log run over the governed post-ex operator, plus the
        live site content served by the compromised host. Loot only runs when
        post-exploitation is pre-authorized (Tier ≥ 1) so the showcase never
        blocks on a human gate; site capture is a scope-enforced, audited HTTP
        GET. Best-effort — a foothold with no web surface simply carries loot
        only, and the whole capture degrades without disturbing the session.
        """

        from ..governance.authorization import AuthorizationDecision, AuthorizationPolicy

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        ctx = self._footholds.get(eid, {}).get(session_id)
        if ctx is None:
            return
        sess = eng.session_manager.get(session_id)
        loot: list[dict[str, str]] = []
        if sess is not None and AuthorizationPolicy(eng.scope).decide(
            "post_exploitation", "T1059"
        ) is AuthorizationDecision.AUTONOMOUS:
            for cmd in self._LOOT_COMMANDS:
                try:
                    result = ctx["postex"].run(sess, cmd)
                except Exception:
                    continue
                if result is not None:
                    loot.append({"command": result.command,
                                 "output": (result.output or "").strip()})
        ctx["loot"] = loot
        with contextlib.suppress(Exception):
            content = self._capture_site_content(eng, finding.asset)
            if content is not None:
                ctx["site_content"] = content
        self._emit(eid, "c2.loot", {"session": session_id, "commands": len(loot),
                                    "site": bool(ctx.get("site_content"))})

    def _capture_site_content(self, eng: Any, host: str) -> dict[str, Any] | None:
        """Fetch the served homepage of the compromised host (captured evidence).

        A real HTTP GET through the scope-enforcing, audited Tool Runner — the
        "stuff of the site" the operator shows the client. The body is
        operator-facing evidence (read from the raw audited result, not surfaced
        to any model), truncated so this stays proof, not bulk retrieval.
        """

        from ..schemas.tools import ToolProfile
        from ..toolrunner.wrappers.http_probe import HttpProbeWrapper

        profile = ToolProfile(preset="default",
                              args={"scheme": "http", "path": "/", "max_bytes": 16384})
        result = eng.tool_runner.run("http_probe", host, profile)
        text = HttpProbeWrapper.body_of(result.raw).decode("utf-8", "replace")
        snippet = text[:2000]
        if not snippet.strip() and not result.parsed.get("status"):
            return None  # nothing served — pure network foothold, loot only
        return {
            "url": f"http://{host}/",
            "status": result.parsed.get("status"),
            "bytes": result.parsed.get("size"),
            "snippet": snippet,
            "truncated": len(text) > len(snippet),
        }

    def _session_json(self, eid: str, session_id: str) -> dict[str, Any]:
        eng = self._manager.get(eid, self._service)
        sess = eng.session_manager.get(session_id)
        ctx = self._footholds.get(eid, {}).get(session_id, {})
        return {
            "id": session_id,
            "host": ctx.get("host") or (sess.host if sess else "?"),
            "status": (sess.status.value if sess else "closed"),
            "technique": ctx.get("technique", "T1190"),
            "proof": ctx.get("proof", {}),
            "loot": ctx.get("loot", []),
            "site_content": ctx.get("site_content"),
            "finding_id": ctx.get("finding_id"),
            "opened_at": ctx.get("opened_at"),
            "kind": (sess.kind.value if sess else "shell"),
        }

    def sessions(self, external_id: str) -> dict[str, Any]:
        """Live C2 sessions + the confirmed findings a new foothold can open on."""

        if not self.is_open(external_id):
            return {"sessions": [], "candidates": []}
        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        live = {s.id for s in eng.session_manager.sessions(active_only=True)}
        sessions = [self._session_json(eid, sid)
                    for sid in self._footholds.get(eid, {})]
        # de-emphasise torn-down sessions but keep them for the record
        for s in sessions:
            if s["id"] not in live and s["status"] != "closed":
                s["status"] = "closed"
        return {"sessions": sessions, "candidates": self.foothold_candidates(external_id)}

    def session_command(self, external_id: str, session_id: str, command: str,
                        *, actor: str = "operator") -> dict[str, Any]:
        """Run one bounded, governed post-exploitation command over a live session."""

        eid = engagement_id_for(external_id)
        ctx = self._footholds.get(eid, {}).get(session_id)
        if ctx is None:
            raise AttackEngineError(f"no live session {session_id!r}")
        eng = self.engagement(external_id)
        sess = eng.session_manager.get(session_id)
        if sess is None:
            raise AttackEngineError("session is no longer live")
        result = ctx["postex"].run(sess, command)
        if result is None:
            raise AttackEngineError("post-ex command denied by the approval gate")
        return {"session_id": session_id, "command": result.command,
                "output": result.output, "ok": result.ok, "host": result.host}

    def teardown_session(self, external_id: str, session_id: str,
                         *, actor: str = "operator") -> dict[str, Any]:
        """Close a live session — bookkeeping AND transport (kill-switchable)."""

        eid = engagement_id_for(external_id)
        ctx = self._footholds.get(eid, {}).get(session_id)
        if ctx is None:
            raise AttackEngineError(f"no live session {session_id!r}")
        closed = ctx["runner"].teardown()
        self._emit(eid, "c2.teardown", {"session": session_id, "closed": closed})
        return {"session_id": session_id, "closed": closed, "status": "closed"}

    def execute_chain(self, external_id: str, chain_id: str,
                      *, actor: str = "operator") -> dict[str, Any]:
        """Run the attack along a composed chain — the "click a chain → attack starts".

        Drives the real engine along the chain: (1) discover+confirm on the chain's
        host so its rungs light up (deterministic sweep → oracles → chainer refresh),
        then (2) if a foothold-capable rung (confirmed command-execution) exists, open
        a live governed C2 session on that host. Governed + audited; runs as a job.
        Returns the chain's realisation state + any session opened.
        """

        from urllib.parse import urlsplit

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        wm = eng.world_model
        chain = None
        if wm is not None:
            chain = next((c for c in wm.chains()
                          if c.id == chain_id or f"chain-{c.id}" == chain_id), None)
        if chain is None:
            raise AttackEngineError(f"attack chain {chain_id!r} not found")
        subject = chain.entry_subject
        host = (urlsplit(subject).hostname if "://" in subject
                else subject.split("/")[0].split(":")[0]) or subject
        self._emit(eid, "chain.execute",
                   {"chain": chain.id, "objective": chain.objective, "host": host})

        # 1. discover + confirm on the chain's host so rungs light up
        web = self._web_targets_or_recon(external_id)
        if web:
            focused = [w for w in web if host in w] or web
            with contextlib.suppress(Exception):
                self._deterministic_web_sweep(external_id, focused)
        with contextlib.suppress(AttackEngineError):
            eng.verify()
        with contextlib.suppress(AttackEngineError):
            eng.correlate()
        self._compose_chains(eng)

        # 2. if a foothold-capable finding on the host is confirmed → open a session
        session: dict[str, Any] | None = None
        for f in eng.store.findings(FindingState.CONFIRMED):
            if self._is_foothold_capable(f) and f.asset == host:
                with contextlib.suppress(AttackEngineError):
                    session = self.establish_foothold(external_id, f.id, actor=actor)
                if session:
                    break

        refreshed = next((c for c in (wm.chains() if wm else []) if c.id == chain.id), chain)
        realised = refreshed.is_realised
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": "Attack Chain", "role": "offensive", "status": "completed",
            "detection_rate": None, "started_at": utcnow().isoformat(),
            "ended_at": utcnow().isoformat(),
            "summary": (f"{chain.objective} — realised={realised} · depth="
                        f"{refreshed.confirmed_depth}/{len(refreshed.steps)}"
                        f"{' · session ' + session['id'] if session else ''}"),
            "steps": [{"phase": s.kind, "target": host,
                       "status": "completed" if s.confirmed else "running",
                       "result": "confirmed" if s.confirmed else "pending"}
                      for s in sorted(refreshed.steps, key=lambda s: s.order)],
            "detections": [], "approvals_created": 0,
        })
        self._emit(eid, "chain.executed",
                   {"chain": chain.id, "realised": realised,
                    "session": session["id"] if session else None})
        return {"chain_id": chain.id, "objective": chain.objective,
                "realised": realised, "confirmed_depth": refreshed.confirmed_depth,
                "steps": len(refreshed.steps), "session": session}

    def execute_recommended_path(
        self, external_id: str, target: str | None = None, *, actor: str = "operator"
    ) -> dict[str, Any]:
        """Execute the AI-recommended most-probable path — turn the narrative into a
        real attack against its target host.

        Drives the same governed, confirmation-grade pipeline the console uses,
        focused on the recommended host: (1) deterministic web sweep on the host so
        oracle-ready candidates graduate, (2) verify → correlate so proposed findings
        become CONFIRMED, (3) network-service exploitation for the non-web surface,
        (4) if a foothold-capable finding on the host is confirmed, open a live,
        governed C2 session on it. Scope-enforced, audited, kill-switchable; runs as
        a background job. Returns the target, confirmations, and any session opened.
        """

        eid = engagement_id_for(external_id)
        eng = self.engagement(external_id)
        host = self._hostkey_np(target) if target else self._primary_target(
            external_id, self.findings(external_id),
            {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0},
        )
        if not host:
            raise AttackEngineError(
                "no target host for the recommended path — run Sensing / Vuln Scan "
                "first so the engine has findings to build a route from"
            )
        self._emit(eid, "path.execute", {"target": host})

        # 1. non-web foothold path FIRST (nmap → exploit module → session), on fresh
        #    state so the exploit module sees un-promoted exposed-service findings
        #    (a prior verify/correlate would graduate them out from under it). Governed.
        with contextlib.suppress(Exception):
            self._exploit_network_services(external_id)
        # 2. discover on the recommended host's web surface (graduate oracle-ready leads)
        web = self._web_targets_or_recon(external_id)
        if web:
            focused = [w for w in web if host in w] or web
            with contextlib.suppress(Exception):
                self._deterministic_web_sweep(external_id, focused)
        # 3. confirm: oracles verify web candidates + correlate promotes everything
        #    (web oracles + the network rce + CVE matches) to CONFIRMED
        with contextlib.suppress(AttackEngineError):
            eng.verify()
        with contextlib.suppress(AttackEngineError):
            eng.correlate()
        self._compose_chains(eng)

        # 4. land a live session on a confirmed foothold-capable finding on the host
        session: dict[str, Any] | None = None
        on_host = [f for f in eng.store.findings(FindingState.CONFIRMED)
                   if self._asset_matches_host(f.asset, host)]
        for f in on_host:
            if self._is_foothold_capable(f):
                try:
                    session = self.establish_foothold(external_id, f.id, actor=actor)
                except AttackEngineError:
                    continue
                if session:
                    break

        host_confirmed = len(on_host)
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": "Recommended Path", "role": "offensive", "status": "completed",
            "detection_rate": None, "started_at": utcnow().isoformat(),
            "ended_at": utcnow().isoformat(),
            "summary": (f"executed recommended path on {host} — "
                        f"{host_confirmed} confirmed finding(s)"
                        f"{' · live session ' + session['id'] if session else ' · no session'}"),
            "steps": [], "detections": [], "approvals_created": 0,
        })
        self._emit(eid, "path.executed",
                   {"target": host, "confirmed": host_confirmed,
                    "session": session["id"] if session else None})
        return {"target": host, "confirmed": host_confirmed, "session": session,
                "reached_foothold": bool(session)}

    def vuln_scan(self, external_id: str) -> tuple[VerifyReport, MatchReport]:
        """Thoroughly screen web surfaces, run the accuracy oracles, correlate CVEs.

        Discovery is a **deterministic, exhaustive sweep** (crawl + broad-scan every
        web surface, probe every discovered parameter, graduate every oracle-ready
        candidate) so findings don't depend on a model's choices — then the
        deterministic oracles promote proposed→verified and the exploitability matcher
        scores + correlates CVEs → CONFIRMED, and the chainer composes the attack path.
        Everything scope-enforced and audited. (The model-driven loop is the campaign's
        adaptive layer; here we want reliable, repeatable coverage.)
        """

        eng = self.engagement(external_id)
        web = self._web_targets_or_recon(external_id)
        if web:
            self._deterministic_web_sweep(external_id, web)
        # Verify + correlate independently — a single tool/rate hiccup in one
        # oracle degrades that finding, it never sinks the whole scan.
        verify = VerifyReport()
        match = MatchReport()
        with contextlib.suppress(AttackEngineError):
            verify = eng.verify()
        with contextlib.suppress(AttackEngineError):
            match = eng.correlate()
        self._compose_chains(eng)
        return verify, match

    def _scope_targets(self, external_id: str) -> list[str]:
        """The engagement's authorized targets (hosts + CIDRs) from its scope."""

        eid = engagement_id_for(external_id)
        scope = self._scopes.get(eid)
        if scope is None:
            return []
        return [*scope.allowed_hosts, *scope.allowed_cidrs]

    def run_campaign(
        self, external_id: str, targets: list[str] | None = None, *, max_rounds: int = 2
    ) -> Any:
        """Run the autonomous adversary campaign — the full kill chain.

        Drives the REAL recon → web → identity specialists via
        :class:`~attack_engine.orchestrator.adversary.AdversaryCampaign`, expanding
        the frontier toward the goal (reach Domain Admin) round by round, sharing the
        engagement's registered world model. Governed (kill-switch/budget) + audited
        (``campaign.start``/``campaign.complete``). Runs verify+correlate afterwards so
        graduated findings promote to CONFIRMED and the attack path reflects the run.
        Returns the :class:`CampaignOutcome`.
        """

        from ..orchestrator.adversary import AdversaryCampaign

        eng = self.engagement(external_id)
        eid = engagement_id_for(external_id)
        tgts = targets or self._scope_targets(external_id)
        campaign = AdversaryCampaign.from_engagement(
            eng, targets=tgts, max_rounds=max_rounds,
        )

        # Live kill-chain progress: record the executing phase + stream a stage event
        # so the console's progression bar shows exactly where we are right now.
        def _progress(event: str, phase: str, round_no: int, **info: object) -> None:
            self._campaign_stage[eid] = phase if event == "phase_start" else None
            self._emit(eid, "campaign.stage",
                       {"event": event, "phase": phase, "round": round_no, **info})

        campaign.progress = _progress
        self._campaign_stage[eid] = "recon"
        self._emit(eid, "campaign.started", {"targets": tgts, "goal": campaign.goal.describe()})
        try:
            outcome = campaign.run()
        finally:
            self._campaign_stage[eid] = None
        # Guarantee thorough web coverage on top of the adaptive campaign: the
        # deterministic sweep graduates every oracle-ready candidate so a run never
        # ends empty just because the planner didn't probe (or classify) a surface.
        with contextlib.suppress(Exception):
            web = self._web_targets_or_recon(external_id)
            if web:
                self._deterministic_web_sweep(external_id, web)
        # Real network-service exploitation: turn any recon'd exposed service that
        # maps to a known exploit (vsftpd/distcc/samba/…) into a CONFIRMED RCE
        # foothold — the non-web half of "reach a foothold". Governed by the
        # exploit_confirm gate (autonomous only on a signed Tier ≥ 1 scope).
        with contextlib.suppress(Exception):
            self._exploit_network_services(external_id)
        # Promote graduated findings: the specialists graduate PROPOSED findings;
        # the deterministic oracles + correlator turn them into CONFIRMED (rule #1).
        with contextlib.suppress(AttackEngineError):
            eng.verify()
        with contextlib.suppress(AttackEngineError):
            eng.correlate()
        self._compose_chains(eng)
        # Execute the composed chains, don't just draw them (pilot #2): land live
        # C2 footholds on the CONFIRMED command-execution points the sweep/exploit
        # produced. This is the step that turns "composes chains but reaches no
        # foothold" into a real breach — governed, autonomous only on a signed
        # Tier ≥ 1 scope, and never blocking the run on a gate.
        sessions: list[str] = []
        with contextlib.suppress(Exception):
            sessions = self._autolaunch_footholds(external_id)
        self._persist_run(eid, {
            "id": f"run-{len(self._runs.get(eid, [])) + 1}",
            "agent_name": "Adversary Campaign", "role": "offensive",
            "status": "completed", "detection_rate": None,
            "started_at": utcnow().isoformat(), "ended_at": utcnow().isoformat(),
            "summary": (
                f"goal_reached={outcome.goal_reached} · rounds={outcome.rounds} · "
                f"stop={outcome.stop_reason} · {outcome.reachable_hosts} hosts · "
                f"{len(outcome.owned_frontier)} principals owned · "
                f"{len(sessions)} footholds · "
                f"{outcome.autonomous_actions} autonomous / {outcome.gated_actions} gated"
            ),
            "steps": [
                {"phase": p.name, "target": p.objective, "status":
                 "completed" if p.met else "running", "result": p.stop_reason}
                for p in outcome.phases
            ],
            "detections": [], "approvals_created": 0,
        })
        self._emit(eid, "campaign.finished",
                   {"goal_reached": outcome.goal_reached, "rounds": outcome.rounds,
                    "stop_reason": outcome.stop_reason, "footholds": len(sessions)})
        return outcome

    def run_agent(self, external_id: str, agent_id: str) -> dict[str, Any]:
        """Dispatch a built-in archetype to its REAL specialist operation.

        Maps the console's four archetypes onto the reasoning engine: surface-mapper
        → recon, web-inquisitor → web reasoning loop + oracles, exploit-confirmer →
        verify + correlate, converter → remediation (per-finding, from the Findings
        tab). Everything scope-enforced, gated, and audited by the engine.
        """

        eid = engagement_id_for(external_id)
        if agent_id in ("surface-mapper", "surface_mapper"):
            self.sense(external_id, self._scope_targets(external_id))
        elif agent_id in ("web-inquisitor", "web_inquisitor"):
            self.vuln_scan(external_id)
        elif agent_id in ("exploit-confirmer", "exploit_confirmer"):
            eng = self.engagement(external_id)
            verify = VerifyReport()
            match = MatchReport()
            with contextlib.suppress(AttackEngineError):
                verify = eng.verify()
            with contextlib.suppress(AttackEngineError):
                match = eng.correlate()
            self._persist_run(eid, {
                "id": f"run-{len(self._runs.get(eid, [])) + 1}",
                "agent_name": "Exploit Confirmer", "role": "offensive",
                "status": "completed", "detection_rate": None,
                "started_at": utcnow().isoformat(), "ended_at": utcnow().isoformat(),
                "summary": (
                    f"{verify.verified} verified · {verify.rejected} rejected · "
                    f"{match.cves_confirmed} CVEs correlated"
                ),
                "steps": [], "detections": [], "approvals_created": 0,
            })
        elif agent_id in ("converter", "remediator"):
            # Remediation is per-finding (propose-only); the console drives it from
            # the Findings tab. Nothing to run engagement-wide here.
            raise AttackEngineError(
                "The Converter proposes remediations per finding — use 'Remediate' on "
                "a finding in the Findings tab."
            )
        else:
            raise AttackEngineError(f"unknown agent {agent_id!r}")
        return {"ok": True, "agent_id": agent_id,
                "runs": self.agent_runs(external_id)[:1]}

    # ── background jobs + live events ───────────────────────────────────────
    def _route_event(self, event: Event) -> None:
        """Fan an engine event into its engagement's SSE queue (thread-safe)."""

        q = self._events.get(event.engagement_id)
        if q is None:
            return
        msg = {
            "ts": utcnow().isoformat(), "type": event.event.value,
            "emitted_by": event.emitted_by, "target": event.target,
            "payload": event.payload,
        }
        with contextlib.suppress(queue.Full):
            q.put_nowait(msg)

    def _emit(self, eid: str, kind: str, payload: dict[str, Any]) -> None:
        q = self._events.get(eid)
        if q is not None:
            with contextlib.suppress(queue.Full):
                q.put_nowait({"ts": utcnow().isoformat(), "type": kind,
                              "emitted_by": "api", "payload": payload})

    def start_job(
        self, external_id: str, kind: str, targets: list[str] | None = None,
        *, agent_id: str | None = None, ref: str | None = None,
    ) -> dict[str, Any]:
        """Start a long op ('sense'/'vuln-scan'/'campaign'/'agent-run') on a worker.

        Returns immediately with a job record so the HTTP request never blocks on
        a minutes-long, Docker- and model-spawning scan. Progress streams over the
        event queue; poll :meth:`jobs` (or subscribe to the SSE stream) for
        completion. Refuses a second concurrent job for the same engagement.
        """

        eid = engagement_id_for(external_id)
        self._events.setdefault(eid, queue.Queue(maxsize=2000))
        with self._job_lock:
            if eid in self._busy:
                raise AttackEngineError("an operation is already running for this engagement")
            self._busy.add(eid)
            job = {
                "id": f"job-{len(self._jobs.get(eid, [])) + 1}", "kind": kind,
                "status": "running", "started_at": time.time(),
                "ended_at": None, "detail": "", "agent_id": agent_id, "ref": ref,
            }
            self._jobs.setdefault(eid, []).append(job)
        self._emit(eid, "job.started", {"job": job["id"], "kind": kind})
        threading.Thread(
            target=self._run_job, args=(external_id, job, kind, targets or []),
            daemon=True,
        ).start()
        # Return a snapshot of the just-created job (status "running"), not the live
        # dict the worker thread mutates — otherwise a fast worker can flip it to
        # "done" before the caller reads it. Live status is polled via :meth:`jobs`.
        return dict(job)

    def _run_job(
        self, external_id: str, job: dict[str, Any], kind: str, targets: list[str]
    ) -> None:
        eid = engagement_id_for(external_id)
        try:
            if kind == "sense":
                self.sense(external_id, targets)
            elif kind == "vuln-scan":
                self.vuln_scan(external_id)
            elif kind == "campaign":
                self.run_campaign(external_id, targets)
            elif kind == "agent-run":
                self.run_agent(external_id, job.get("agent_id") or "")
            elif kind == "foothold":
                self.establish_foothold(external_id, job.get("ref") or "")
            elif kind == "chain-exec":
                self.execute_chain(external_id, job.get("ref") or "")
            elif kind == "path-exec":
                self.execute_recommended_path(external_id, job.get("ref") or None)
            else:
                raise AttackEngineError(f"unknown job kind {kind!r}")
            job["status"] = "done"
        except Exception as exc:
            job["status"] = "error"
            job["detail"] = f"{type(exc).__name__}: {exc}"
            self._emit(eid, "job.error", {"job": job["id"], "detail": job["detail"]})
        finally:
            job["ended_at"] = time.time()
            with self._job_lock:
                self._busy.discard(eid)
            self._emit(eid, "job.finished", {"job": job["id"], "status": job["status"]})

    def jobs(self, external_id: str) -> list[dict[str, Any]]:
        return list(reversed(self._jobs.get(engagement_id_for(external_id), [])))

    async def event_stream(self, external_id: str) -> AsyncIterator[str]:
        """SSE generator — drains the engagement's event queue as it fills."""

        eid = engagement_id_for(external_id)
        q = self._events.setdefault(eid, queue.Queue(maxsize=2000))
        yield "retry: 3000\n\n"
        while True:
            drained = False
            with contextlib.suppress(queue.Empty):
                while True:
                    msg = q.get_nowait()
                    drained = True
                    yield f"data: {json.dumps(msg)}\n\n"
            if not drained:
                yield ": keep-alive\n\n"
            await asyncio.sleep(1.0)

    # ── reads (console-shaped JSON) ─────────────────────────────────────────
    def assets(self, external_id: str) -> list[dict[str, Any]]:
        return [asset_to_json(a) for a in self.engagement(external_id).store.assets()]

    @staticmethod
    def _console_status(
        base: str, has_remediation: bool, retest: dict[str, Any] | None
    ) -> str:
        """Fold the remediation lifecycle into the console's finding status.

        A bare finding is ``open`` (or ``false-positive`` if rejected). Once a
        remediation is proposed it reads ``remediating``; a re-test that clears it
        is ``closed``; a re-test that still fires is ``retest`` (fix didn't hold).
        """

        if retest is not None:
            return "closed" if retest.get("fixed") else "retest"
        if has_remediation:
            return "remediating"
        return base

    def findings(self, external_id: str) -> list[dict[str, Any]]:
        eng = self.engagement(external_id)
        retests = self._retests.get(engagement_id_for(external_id), {})
        rows: list[dict[str, Any]] = []
        for f in eng.store.findings():
            row = finding_to_json(f)
            rems = eng.store.remediations(f.id)
            retest = retests.get(f.id)
            row["status"] = self._console_status(row["status"], bool(rems), retest)
            if rems and not row.get("remediation"):
                row["remediation"] = rems[0].content
            if retest is not None:
                row["retest"] = retest
            rows.append(row)
        return rows

    def audit_events(
        self,
        external_id: str | None = None,
        *,
        limit: int = 500,
        event_type: str | None = None,
        actor: str | None = None,
    ) -> list[dict[str, Any]]:
        """Newest-first console audit events off the engine's real chain."""

        eid = engagement_id_for(external_id) if external_id else None
        entries = self._engine.audit.entries(engagement_id=eid)
        if event_type:
            entries = [e for e in entries if e.action == event_type]
        if actor:
            entries = [e for e in entries if e.actor == actor]
        entries = list(reversed(entries))[: max(0, limit)]
        return [audit_entry_to_json(e) for e in entries]

    def audit_verify(self, external_id: str | None = None) -> dict[str, Any]:
        """Recompute the real hash chain → console verify shape."""

        eid = engagement_id_for(external_id) if external_id else None
        entries = self._engine.audit.entries(engagement_id=eid)
        head = entries[-1] if entries else None
        try:
            self._engine.audit.verify()
            return {
                "valid": True,
                "count": len(entries),
                "head_hash": head.entry_hash if head else None,
            }
        except AuditIntegrityError as exc:
            return {
                "valid": False,
                "broken_at_seq": getattr(exc, "seq", None),
                "count": len(entries),
            }

    def invocation_raw(self, invocation_id: str) -> dict[str, Any] | None:
        """Raw sandbox output for a tool invocation (by its audit entry hash)."""

        backend = self._engine.audit.backend
        raw = backend.get_raw(invocation_id) if hasattr(backend, "get_raw") else None
        entry = next(
            (e for e in self._engine.audit.entries() if e.entry_hash == invocation_id),
            None,
        )
        if raw is None and entry is None:
            return None
        return {
            "id": invocation_id,
            "raw": raw.decode("utf-8", "replace") if raw else "",
            "action": entry.action if entry else None,
            "target": entry.target if entry else None,
            "payload": entry.payload if entry else {},
        }

    def record_governance(
        self,
        external_id: str,
        *,
        actor: str,
        action: str,
        target: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Append a lifecycle / governance action to the engine's hash chain.

        The console drives the whole engagement lifecycle (sign RoE, activate,
        pause, halt, resume, archive, approvals) through the HTTP shell; those
        actions must land in the *same* tamper-evident chain as the engine's own
        tool/model events, attributed to the real operator (not the internal
        service principal). The chain is engine-global and filtered by
        ``engagement_id``, so this works even before an engagement is opened
        (e.g. signing a draft RoE).
        """

        self._engine.audit.append(
            engagement_id=engagement_id_for(external_id),
            actor=actor,
            action=action,
            target=target,
            payload=payload or {},
        )

    def invocations(self, external_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        """Tool invocations for the Console, derived from the tool audit trail."""

        eid = engagement_id_for(external_id)
        out: list[dict[str, Any]] = []
        for e in self._engine.audit.entries(engagement_id=eid):
            if not e.action.startswith("tool."):
                continue
            payload = e.payload or {}
            refused = e.action == "tool.refused"
            out.append({
                "id": e.entry_hash,
                "tool_id": payload.get("tool") or "tool",
                "target": e.target,
                "intensity": payload.get("preset") or "recon",
                "scope_check_result": {
                    "allow": not refused,
                    "reason": payload.get("reason", "" if not refused else "refused"),
                },
                "status": "refused" if refused else "completed",
                "exit_status": payload.get("exit_code"),
                "started_at": e.ts,
            })
        return list(reversed(out))[: max(0, limit)]

    # ── CVE feed (cache + refresh) ─────────────────────────────────────────
    @staticmethod
    def _cve_json(rec: Any) -> dict[str, Any]:
        products = [a.product for a in rec.affected]
        return {
            "id": rec.id,
            "cve_id": rec.id,
            "product": products[0] if products else "",
            "products": products,
            "versions": [],
            "cvss": rec.cvss,
            "kev": rec.kev,
            "epss": rec.epss,
            "exploit_known": rec.has_public_exploit,
            "cwe": rec.cwe,
            "summary": rec.description,
        }

    def cve_cache(self) -> list[dict[str, Any]]:
        """The CVE records currently loaded in the engine feed."""

        records = getattr(self._engine.feed, "records", None)
        if not records:
            return []
        return [self._cve_json(r) for r in records]

    def refresh_cve(self, external_id: str, *, actor: str) -> dict[str, Any]:
        """Rebuild the CVE feed from config and re-correlate the engagement.

        Re-reads the configured NVD/KEV/EPSS files (or the seed feed if none are
        configured), swaps it into the engine and the open engagement, and re-runs
        exploitability correlation so new CVE matches surface as findings.
        """

        from ..engine import build_cve_feed

        feed = build_cve_feed(self._engine.settings)
        self._engine.feed = feed
        records = getattr(feed, "records", [])
        source = "files" if self._engine.settings.cve_nvd_path else "seed"
        findings_after = 0
        if self.is_open(external_id):
            eng = self.engagement(external_id)
            eng.feed = feed
            with contextlib.suppress(AttackEngineError):
                eng.correlate()
            findings_after = len(eng.store.findings())
        self.record_governance(
            external_id, actor=actor, action="cve.refreshed",
            payload={"records": len(records), "source": source},
        )
        return {"records": len(records), "source": source, "findings": findings_after}

    # ── model gateway: inference + adversary copilot (BYOM, rule #4) ────────
    def _chat_messages(self, messages: list[dict[str, Any]]) -> list[Any]:
        from ..gateway.types import ChatMessage

        makers = {
            "system": ChatMessage.system,
            "assistant": ChatMessage.assistant,
            "user": ChatMessage.user,
        }
        out = []
        for m in messages:
            content = m.get("content") or m.get("text") or ""
            if not content:
                continue
            out.append(makers.get(m.get("role", "user"), ChatMessage.user)(content))
        return out

    def model_infer(
        self,
        *,
        messages: list[dict[str, Any]],
        sensitivity: str = "internal",
        route: str | None = None,
        actor: str = "operator",
        engagement_id: str | None = None,
    ) -> dict[str, Any]:
        """Route a completion through the BYOM gateway (playground).

        Sensitivity ``sensitive``/``airgapped`` is pinned to the LOCAL tier
        (SEC-05 — sensitive data never leaves on a hosted model); otherwise an
        explicit route override wins, else the frontier tier. Every call is
        audited by the gateway itself.
        """

        from ..schemas.agentspec import ModelTier

        if sensitivity in ("sensitive", "airgapped"):
            tier, forced_local = ModelTier.LOCAL, True
        elif route == "local":
            tier, forced_local = ModelTier.LOCAL, False
        elif route == "frontier":
            tier, forced_local = ModelTier.FRONTIER, False
        else:
            tier, forced_local = ModelTier.FRONTIER, False
        eid = engagement_id_for(engagement_id) if engagement_id else None
        resp = self._engine.gateway.complete(
            self._chat_messages(messages), tier=tier, engagement_id=eid, actor=actor
        )
        return {
            "route": resp.tier or resp.model,
            "model": resp.model,
            "text": resp.text,
            "redaction_applied": forced_local,
            "usage": {
                "token_in": resp.usage.prompt_tokens,
                "token_out": resp.usage.completion_tokens,
                "latency_ms": 0,
                "cost": 0,
            },
        }

    _RED_SCOPE_SYSTEM = (
        "You are the 8π Red Scope copilot — an adversary-emulation advisor for an "
        "authorized red-team operator. You operate strictly inside a signed scope and "
        "the platform's propose-vs-confirm rules: you propose attack reasoning, "
        "prioritization, and next steps; deterministic engine oracles confirm. Be "
        "concise, technical, and actionable. Never invent findings as fact."
    )

    def red_scope_chat(
        self,
        *,
        message: str,
        history: list[dict[str, Any]] | None = None,
        actor: str = "operator",
    ) -> dict[str, Any]:
        """The Red Scope adversary copilot — a gateway-backed chat (BYOM)."""

        from ..gateway.types import ChatMessage

        convo = [ChatMessage.system(self._RED_SCOPE_SYSTEM)]
        convo.extend(self._chat_messages(history or []))
        convo.append(ChatMessage.user(message))
        from ..schemas.agentspec import ModelTier

        resp = self._engine.gateway.complete(
            convo, tier=ModelTier.FRONTIER, actor=actor
        )
        return {"reply": resp.text, "model": resp.model}

    def save_red_scope_agent(
        self, draft: dict[str, Any], *, actor: str = "operator"
    ) -> dict[str, Any]:
        """Persist a Red Scope copilot preset for this session (in-memory)."""

        agent = {
            **draft,
            "id": draft.get("id") or f"rs-{utcnow().strftime('%Y%m%d%H%M%S')}",
            "created_by": actor,
            "created_at": utcnow().isoformat(),
        }
        self._red_scope_agents.append(agent)
        return agent

    def model_calls(self, external_id: str | None = None) -> list[dict[str, Any]]:
        """Model gateway calls, derived from the model audit trail."""

        eid = engagement_id_for(external_id) if external_id else None
        out: list[dict[str, Any]] = []
        for e in self._engine.audit.entries(engagement_id=eid):
            if not e.action.startswith("model."):
                continue
            p = e.payload or {}
            out.append({
                "id": e.entry_hash, "engagement_id": e.engagement_id,
                "route": p.get("tier") or p.get("model") or "local",
                "model": p.get("model"), "purpose": p.get("purpose", "reason"),
                "sensitivity": p.get("sensitivity", "internal"),
                "cost": p.get("cost", 0), "ts": e.ts,
            })
        return list(reversed(out))

    def agent_runs(self, external_id: str) -> list[dict[str, Any]]:
        return list(reversed(self._runs.get(engagement_id_for(external_id), [])))

    def agent_run(self, run_id: str) -> dict[str, Any] | None:
        """A single recorded agent/campaign run by id (across open engagements)."""

        for runs in self._runs.values():
            for r in runs:
                if r["id"] == run_id:
                    return r
        return None

    # ── human approvals (gated actions over HTTP) ──────────────────────────
    def approvals(
        self, external_id: str, status: str | None = None
    ) -> list[dict[str, Any]]:
        return self._approvals.approvals(engagement_id_for(external_id), status)

    def pending_approvals(self, external_id: str) -> int:
        return self._approvals.pending_count(engagement_id_for(external_id))

    def resolve_approval(
        self, approval_id: str, *, approved: bool, approver: str, reason: str = ""
    ) -> bool:
        """Approve/deny a parked gate; unblocks the waiting engine worker thread."""

        return self._approvals.resolve(
            approval_id, approved=approved, approver=approver, reason=reason
        )

    # ── remediation lifecycle (propose fix → re-test) ──────────────────────
    @staticmethod
    def _remediation_json(rem: Any) -> dict[str, Any]:
        return {
            "id": rem.id, "finding_id": rem.finding_id, "kind": rem.kind.value,
            "title": rem.title, "content": rem.content, "status": rem.status.value,
            "proposed_by": rem.proposed_by, "created_at": rem.created_at,
        }

    def _find_engagement_of(self, finding_id: str) -> tuple[str, Any] | None:
        """Locate the open engagement holding ``finding_id`` (engine id, handle)."""

        for eid in self._manager.list_open(self._service):
            eng = self._manager.get(eid, self._service)
            if eng.store.get_finding(finding_id) is not None:
                return eid, eng
        return None

    def remediate_finding(self, finding_id: str, *, actor: str) -> dict[str, Any]:
        """Propose a remediation for a finding (propose-only; never auto-applies).

        Reuses the real :class:`Converter` archetype to generate the control (patch
        / config / ticket) deterministically. Applying a change on the customer's
        estate stays a separate, human-gated action — this only proposes.
        """

        from ..agents.archetypes.converter import Converter

        located = self._find_engagement_of(finding_id)
        if located is None:
            raise AttackEngineError(f"finding {finding_id!r} not found in any open engagement")
        eid, eng = located
        finding = eng.store.get_finding(finding_id)
        existing = eng.store.remediations(finding_id)
        if existing:
            rem = existing[0]
        else:
            spec = load_spec(_SPECS_DIR / "converter.yaml").model_copy(
                update={"scope_ref": eid}
            )
            agent = build_agent(spec, eng.context, eng.registry)
            assert isinstance(agent, Converter)
            rem = agent._propose(finding)
            eng.store.add_remediation(rem, emitted_by="api")
        self.record_governance(
            eid, actor=actor, action="finding.remediation_proposed",
            target=finding.asset,
            payload={"finding_id": finding_id, "remediation_id": rem.id,
                     "kind": rem.kind.value},
        )
        return self._remediation_json(rem)

    def retest_finding(self, finding_id: str, *, actor: str) -> dict[str, Any]:
        """Re-run the exact confirming check and report whether it still fires.

        Uses the engine's :class:`RetestRunner` (scope-enforced, audited). A fix
        that holds marks any proposed remediation ``verified_fixed`` and the
        console finding ``closed``; a check that still fires is escalated.
        """

        from ..orchestrator.retest import RetestRunner
        from ..schemas.remediation import RemediationStatus
        from ..verify.context import VerifyContext

        located = self._find_engagement_of(finding_id)
        if located is None:
            raise AttackEngineError(f"finding {finding_id!r} not found in any open engagement")
        eid, eng = located
        finding = eng.store.get_finding(finding_id)
        ctx = VerifyContext(
            engagement_id=eid, tool_runner=eng.tool_runner,
            store=eng.store, audit=eng.audit,
        )
        result = RetestRunner(ctx, eng.feed).retest(finding)
        rems = eng.store.remediations(finding_id)
        if rems:
            new_status = (
                RemediationStatus.VERIFIED_FIXED if result.fixed
                else RemediationStatus.PERSISTED
            )
            eng.store.update_remediation(rems[0].model_copy(update={"status": new_status}))
        row = {"finding_id": finding_id, "fixed": result.fixed,
               "closed": result.fixed, "detail": result.detail,
               "ts": utcnow().isoformat()}
        self._retests.setdefault(eid, {})[finding_id] = row
        self.record_governance(
            eid, actor=actor, action="finding.retest", target=finding.asset,
            payload={"finding_id": finding_id, "fixed": result.fixed,
                     "detail": result.detail},
        )
        return row

    def asset_detail(self, external_id: str, asset_id: str) -> dict[str, Any] | None:
        """One asset + its findings + tool invocations that touched it."""

        assets = self.assets(external_id)
        asset = next((a for a in assets if a["id"] == asset_id), None)
        if asset is None:
            return None
        addr = asset["identifiers"].get("ip") or asset["identifiers"].get("host")
        findings = [f for f in self.findings(external_id) if f["asset_id"] == addr]
        invs = [i for i in self.invocations(external_id) if i["target"] == addr]
        return {"asset": asset, "findings": findings, "parent": None,
                "children": [], "invocations": invs}

    def threat_map(self, external_id: str) -> dict[str, Any]:
        return views.build_threat_map(self.assets(external_id), self.findings(external_id))

    def _engine_routes(self, external_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The REAL engine routes for the path/tree views: WebChainer attack chains
        + AD Domain-Admin paths, serialized. Empty + safe when closed."""

        chains: list[dict[str, Any]] = []
        ad_paths: list[dict[str, Any]] = []
        if self.is_open(external_id):
            wm = self.engagement(external_id).world_model
            if wm is not None:
                with contextlib.suppress(Exception):
                    chains = [
                        {"id": c.id, "objective": c.objective, "entry": c.entry_subject,
                         "confirmed_depth": c.confirmed_depth, "is_realised": c.is_realised,
                         "steps": [{"order": s.order, "kind": s.kind, "subject": s.subject,
                                    "confirmed": s.confirmed}
                                   for s in sorted(c.steps, key=lambda s: s.order)]}
                        for c in wm.chains()
                    ]
                with contextlib.suppress(Exception):
                    ad_paths = [
                        {"start": p.start, "target": p.target,
                         "techniques": [e.technique for e in p.edges]}
                        for p in wm.domain_admin_paths()
                    ]
        return chains, ad_paths

    def attack_path(self, external_id: str) -> dict[str, Any]:
        # Feed the REAL engine routes (WebChainer attack chains + AD Domain-Admin
        # paths) into the view so the console renders the actual chained kill chain,
        # not just a flat per-finding list.
        chains, ad_paths = self._engine_routes(external_id)
        return views.build_attack_path(
            self.assets(external_id), self.findings(external_id),
            chains=chains, ad_paths=ad_paths,
        )

    def attack_tree(self, external_id: str) -> dict[str, Any]:
        """The whole attack as a kill-chain tree (the Threat Map view).

        Assembles reachable assets + CONFIRMED/candidate findings + the real engine
        routes + live C2 sessions (with their proof-of-impact) + the world-model
        belief state into a hierarchical, phase-layered breach tree. Empty, valid
        shape when the engagement is closed — never an error.
        """

        empty: dict[str, Any] = {"phases": [], "nodes": [], "edges": [], "summary": {}}
        if not self.is_open(external_id):
            return empty
        chains, ad_paths = self._engine_routes(external_id)
        sessions: list[dict[str, Any]] = []
        with contextlib.suppress(Exception):
            sessions = self.sessions(external_id).get("sessions", [])
        world_model: dict[str, Any] = {}
        with contextlib.suppress(Exception):
            world_model = self.world_model_view(external_id)
        return views.build_attack_tree(
            self.assets(external_id), self.findings(external_id),
            chains=chains, ad_paths=ad_paths, sessions=sessions, world_model=world_model,
        )

    #: The canonical kill-chain the progress bar walks (key, label, what it means).
    _KILL_CHAIN: tuple[tuple[str, str, str], ...] = (
        ("recon", "Recon", "Map the attack surface"),
        ("confirm", "Confirm", "Prove exploitable findings (oracles)"),
        ("foothold", "Foothold", "Land a session on a target"),
        ("escalate", "Escalate", "Own credentials / privileges"),
        ("lateral", "Lateral", "Reuse access across hosts"),
        ("objective", "Objective", "Reach Domain Admin"),
    )
    #: Live campaign phase → the kill-chain stage it is actively working on.
    _PHASE_TO_STAGE = {"recon": "recon", "web": "foothold", "identity": "escalate"}

    def campaign_status(self, external_id: str) -> dict[str, Any]:
        """Derive the live kill-chain progression from the REGISTERED world model.

        The world model is the source of truth for the attack path, so each stage's
        'done' is a real milestone in it (assets mapped, findings CONFIRMED, a foothold
        chain realised, principals owned, a Domain-Admin path surfaced). The currently
        executing campaign phase (if any) marks the active stage. Honest, empty-safe.
        """

        eid = engagement_id_for(external_id)
        running_phase = self._campaign_stage.get(eid)
        # A live signal for ANY running work, not just a campaign: a plain Sense /
        # Vuln Scan / agent-run job also lights the bar so the operator always sees
        # "what's happening right now".
        running_job = next(
            (j for j in self._jobs.get(eid, []) if j["status"] == "running"), None
        )
        job_kind = running_job["kind"] if running_job else None
        active_phase = running_phase or job_kind
        is_running = running_phase is not None or running_job is not None
        # Epoch start + elapsed of the running op, so the console shows a live
        # "running for N s" timer and the operator knows a long scan is progressing.
        started_at = running_job["started_at"] if running_job else None
        elapsed = (time.time() - started_at) if started_at else 0.0
        base = {
            "running": is_running,
            "active_phase": active_phase,
            "current": None,
            "started_at": started_at,
            "elapsed_sec": round(elapsed, 1),
            "stages": [{"key": k, "label": lbl, "detail": d, "status": "pending"}
                       for k, lbl, d in self._KILL_CHAIN],
        }
        if not self.is_open(external_id):
            return base

        eng = self.engagement(external_id)
        wm = eng.world_model
        findings = self.findings(external_id)
        confirmed = [f for f in findings if f.get("exploitability") == "confirmed"]
        reachable = len(wm.reachable_assets()) if wm else len(self.assets(external_id))
        owned = list(wm.owned_principals) if wm else []
        chains = wm.chains() if wm else []
        da_paths = wm.domain_admin_paths() if wm else []
        foothold = any(c.is_realised for c in chains) or any(
            (str(f.get("technique_ref") or "") in ("T1059", "T1190"))
            and f.get("exploitability") == "confirmed"
            and any(w in (f.get("title") or "").lower()
                    for w in ("command", "rce", "shell", "cmdi", "injection"))
            for f in findings
        )
        done = {
            "recon": reachable >= 1 or bool(self.assets(external_id)),
            "confirm": len(confirmed) >= 1,
            "foothold": foothold,
            "escalate": len(owned) >= 1,
            "lateral": len(owned) >= 1 and reachable > 1,
            "objective": bool(da_paths) or bool(owned and da_paths),
        }
        counts = {
            "recon": reachable, "confirm": len(confirmed),
            "foothold": sum(1 for c in chains if c.is_realised),
            "escalate": len(owned), "lateral": max(reachable - 1, 0) if owned else 0,
            "objective": len(da_paths),
        }
        # Which stage is actively working: campaign phase → stage, else the running
        # job kind → stage, else the first not-yet-done stage.
        job_stage = {"sense": "recon", "vuln-scan": "confirm",
                     "campaign": "recon", "agent-run": "confirm"}
        active_stage = (
            self._PHASE_TO_STAGE.get(running_phase or "")
            or (job_stage.get(job_kind or "") if is_running else None)
        )
        first_pending = next((k for k, *_ in self._KILL_CHAIN if not done[k]), None)
        current = active_stage or first_pending
        stages = []
        for k, lbl, d in self._KILL_CHAIN:
            if done[k]:
                status = "done"
            elif k == current:
                status = "active"
            else:
                status = "pending"
            stages.append({"key": k, "label": lbl, "detail": d,
                           "status": status, "count": counts.get(k, 0)})
        return {"running": is_running, "active_phase": active_phase,
                "current": current, "started_at": started_at,
                "elapsed_sec": round(elapsed, 1), "stages": stages}

    def authorization_view(
        self, external_id: str, roe: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """The rules-of-engagement control room: what the AI is authorized to do.

        Classifies every ATT&CK technique, tool, and high-impact action against the
        engagement's signed RoE using the SAME policy the runtime enforces:
        **autonomous** (pre-authorized → runs unattended), **gated** (runs but human-
        approved), **gated-evasion** (defense-evasion — always gated), or **denied**
        (tool on the denylist / off an exclusive allowlist). The operator toggles a
        row → the console edits the RoE (PUT /roe) → re-activate applies it. Uses the
        live scope when active, else a preview scope from the stored RoE.
        """

        from ..attack.catalog import build_library
        from ..governance.authorization import AuthorizationDecision, AuthorizationPolicy
        from ..orchestrator.adversary import EVASION_TECHNIQUES

        if self.is_open(external_id):
            scope = self.engagement(external_id).scope
            live = True
        elif roe is not None:
            scope = scope_from_roe(external_id, roe,
                                   authorized_by=roe.get("signed_by"),
                                   signature=roe.get("signature"))
            live = False
        else:
            return {"live": False, "tier": 0, "read_only": True, "signed": False,
                    "techniques": [], "tools": [], "actions": [], "counts": {}}

        r = scope.roe
        policy = AuthorizationPolicy(scope)
        techniques = []
        for t in build_library().all():
            if t.id in EVASION_TECHNIQUES:
                status = "gated-evasion"
            elif policy.decide(t.id, t.id) is AuthorizationDecision.AUTONOMOUS:
                status = "autonomous"
            else:
                status = "gated"
            techniques.append({
                "id": t.id, "name": t.name, "tactic": t.tactic.value,
                "status": status, "authorized": t.id in r.authorized_techniques,
                "evasion": t.id in EVASION_TECHNIQUES,
            })
        tools = []
        registry = self._engine.registry
        names = sorted(registry.names()) if hasattr(registry, "names") else []
        for n in names:
            forbidden = n in r.forbidden_tools
            on_allow = n in r.allowed_tools
            allow_ok = (not r.allowed_tools) or on_allow
            licensed = False
            with contextlib.suppress(Exception):
                licensed = bool(getattr(registry.resolve(n), "licensed", False))
            tools.append({
                "tool": n, "status": "denied" if (forbidden or not allow_ok) else "allowed",
                "forbidden": forbidden, "on_allowlist": on_allow, "licensed": licensed,
            })
        actions = [{"action": a, "status": "gated", "reason": "high-impact — always gated"}
                   for a in sorted(r.high_impact_actions)]
        counts = {
            "autonomous": sum(1 for t in techniques if t["status"] == "autonomous"),
            "gated": sum(1 for t in techniques if t["status"] in ("gated", "gated-evasion")),
            "tools_allowed": sum(1 for t in tools if t["status"] == "allowed"),
            "tools_denied": sum(1 for t in tools if t["status"] == "denied"),
        }
        return {
            "live": live, "tier": r.autonomy_tier, "read_only": r.read_only,
            "signed": scope.is_signed(), "allowlist_mode": bool(r.allowed_tools),
            "techniques": techniques, "tools": tools, "actions": actions, "counts": counts,
        }

    def world_model_view(self, external_id: str) -> dict[str, Any]:
        """Serialize the engagement's registered world model for the console.

        The belief state the reasoning loops + campaign share and grow: open/graduated
        hypotheses (with fused confidence + provenance), attack chains and how far each
        is realised, owned principals, and any surfaced Domain-Admin paths. Empty, valid
        shape when the engagement is closed — never an error.
        """

        empty = {"hypotheses": [], "chains": [], "owned_principals": [],
                 "domain_admin_paths": [], "reachable_assets": 0,
                 "counts": {"hypotheses": 0, "graduated": 0, "chains": 0,
                            "chains_realised": 0, "owned_principals": 0, "da_paths": 0}}
        if not self.is_open(external_id):
            return empty
        wm = self.engagement(external_id).world_model
        if wm is None:
            return empty
        hyps = wm.hypotheses()
        chains = wm.chains()
        da_paths = wm.domain_admin_paths()
        return {
            "hypotheses": [
                {"id": h.id, "subject": h.subject, "kind": h.kind, "title": h.title,
                 "status": h.status.value, "confidence": round(h.confidence, 3),
                 "observations": len(h.observations), "finding_id": h.finding_id,
                 "suggested_tools": list(h.suggested_tools)}
                for h in sorted(hyps, key=lambda x: x.confidence, reverse=True)[:100]
            ],
            "chains": [
                {"id": c.id, "objective": c.objective, "entry": c.entry_subject,
                 "steps": [{"kind": s.kind, "subject": s.subject,
                            "confirmed": s.confirmed} for s in
                           sorted(c.steps, key=lambda s: s.order)],
                 "confirmed_depth": c.confirmed_depth, "is_realised": c.is_realised}
                for c in chains
            ],
            "owned_principals": list(wm.owned_principals),
            "domain_admin_paths": [
                {"start": p.start, "target": p.target, "length": len(p.edges),
                 "techniques": [e.technique for e in p.edges]}
                for p in da_paths
            ],
            "reachable_assets": len(wm.reachable_assets()),
            "counts": {
                "hypotheses": len(hyps),
                "graduated": sum(1 for h in hyps if h.finding_id),
                "chains": len(chains),
                "chains_realised": sum(1 for c in chains if c.is_realised),
                "owned_principals": len(wm.owned_principals),
                "da_paths": len(da_paths),
            },
        }

    _ATTACK_PATH_SYSTEM = (
        "You are the 8π attack-path narrator for an authorized red-team engagement. "
        "Given the engine's confirmed/observed findings and the asset attack surface, "
        "explain — as a real adversary would reason — the most likely breach route from "
        "an external entry point to the crown jewels: which finding gives initial access, "
        "how it chains to the next hop, and the impact at the objective. Ground every "
        "claim in the provided findings (cite titles/CVEs); never invent a finding. Use "
        "short markdown sections. Be concise, technical, and honest about uncertainty."
    )

    def attack_path_narrative(
        self, external_id: str, *, actor: str = "operator"
    ) -> dict[str, Any]:
        """Model-generated narrative of the breach route over the REAL findings (BYOM).

        Builds the prompt from the engine's findings + attack-path surface + world-model
        beliefs and routes it through the gateway (rule #4). Returns the full text + route
        + usage; the API streams it as deltas. Honest when there is nothing to narrate.
        """

        from ..gateway.types import ChatMessage
        from ..schemas.agentspec import ModelTier

        eid = engagement_id_for(external_id)
        findings = self.findings(external_id) if self.is_open(external_id) else []
        ap = self.attack_path(external_id)
        if not findings and not ap.get("paths"):
            return {"text": "", "route": "none", "empty": True, "target": None,
                    "usage": {"token_in": 0, "token_out": 0, "latency_ms": 0, "cost": 0}}
        sev_rank = {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0}
        target = self._primary_target(external_id, findings, sev_rank)
        top = sorted(
            findings,
            key=lambda f: (f.get("exploitability") == "confirmed",
                           sev_rank.get(str(f.get("severity") or ""), 0)),
            reverse=True,
        )[:25]
        lines = []
        for f in top:
            cves = f.get("cve_refs") or []
            lines.append(
                f"- {f.get('title')} | sev={f.get('severity')} | "
                f"exploitability={f.get('exploitability')} | target={f.get('asset_id') or '?'}"
                f"{' | ' + ', '.join(cves) if cves else ''}"
            )
        context = (
            f"Engagement findings ({len(findings)} total, showing {len(top)}):\n"
            + "\n".join(lines)
            + f"\n\nAttack surface: {ap['stats']['entry']} entry points, "
            f"{ap['stats']['crown']} crown jewels, {ap['stats']['paths']} candidate paths."
        )
        convo = [
            ChatMessage.system(self._ATTACK_PATH_SYSTEM),
            ChatMessage.user(
                "Narrate the most probable breach path from the findings below.\n\n"
                + context
            ),
        ]
        resp = self._engine.gateway.complete(
            convo, tier=ModelTier.FRONTIER, engagement_id=eid, actor=actor
        )
        return {
            "text": resp.text,
            "route": resp.tier or resp.model,
            "target": target,
            "usage": {"token_in": resp.usage.prompt_tokens,
                      "token_out": resp.usage.completion_tokens,
                      "latency_ms": 0, "cost": 0},
        }

    def _primary_target(
        self, external_id: str, findings: list[dict[str, Any]], sev_rank: dict[str, int]
    ) -> str | None:
        """The host the most-probable path converges on — the one aggregating the
        most actionable findings (confirmed/high weighted), restricted to in-scope
        hosts so an off-scope third-party candidate can never become the target."""

        scope_targets = self._scope_targets(external_id)
        score: dict[str, float] = {}
        for f in findings:
            host = f.get("asset_id")
            if not host:
                continue
            hk = self._hostkey_np(str(host))
            # keep only in-scope hosts when we know the scope (CIDR-aware, so a host
            # inside an authorized /24 counts and an off-scope third-party does not)
            if scope_targets and not any(self._asset_matches_host(t, hk) for t in scope_targets):
                continue
            expl = f.get("exploitability")
            weight = 5 if expl == "confirmed" else 2 if expl == "reachable" else 0
            score[str(host)] = score.get(str(host), 0.0) + weight + sev_rank.get(
                str(f.get("severity") or ""), 0) + 1
        return max(score, key=lambda h: score[h]) if score else None

    @staticmethod
    def _hostkey_np(addr: str) -> str:
        """Address → bare host (strip CIDR/port), for scope/target matching."""

        return str(addr or "").split("/", 1)[0].split(":", 1)[0].strip()

    def _asset_matches_host(self, asset: str, host: str) -> bool:
        """Whether ``asset`` (a host, IP, or CIDR/target) refers to ``host``.

        Handles the two ways findings key their asset: a bare host (exact match)
        and a scan target that is a CIDR containing the host (network-exploit
        findings are keyed by the scanned CIDR, not the individual IP)."""

        import ipaddress

        if self._hostkey_np(asset) == host:
            return True
        if "/" in str(asset):
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(asset, strict=False)
            except ValueError:
                return False
        return False

    def report_summary(self, external_id: str) -> dict[str, Any]:
        verdict = self.audit_verify(external_id)
        return views.build_report_summary(
            self.findings(external_id), len(self.assets(external_id)),
            verdict.get("count", 0), bool(verdict.get("valid")),
        )

    def stats(self) -> dict[str, Any]:
        """Aggregate counts across all open engagements for the dashboard."""

        open_ids = self._manager.list_open(self._service)
        by_severity = {"crit": 0, "high": 0, "med": 0, "low": 0, "info": 0}
        assets = findings_open = pending_approvals = 0
        for eid in open_ids:
            eng = self._manager.get(eid, self._service)
            assets += len(eng.store.assets())
            pending_approvals += self._approvals.pending_count(eid)
            for f in eng.store.findings():
                row = finding_to_json(f)
                if row["status"] not in ("closed", "false-positive"):
                    findings_open += 1
                    by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        return {
            "engagements": len(open_ids),
            "engagements_by_status": {"active": len(open_ids)},
            "assets": assets,
            "findings_open": findings_open,
            "findings_by_severity": by_severity,
            "tool_invocations": len(self._engine.audit.entries()),
            "pending_approvals": pending_approvals,
            "model_calls": 0,
            "model_spend": 0,
            "agents": 0,
        }
