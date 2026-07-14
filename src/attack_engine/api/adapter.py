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

from ..agents.loader import load_spec
from ..config import Settings
from ..correlate.matcher import MatchReport
from ..engine import Engagement, Engine
from ..errors import AttackEngineError, AuditIntegrityError
from ..governance.rbac import AccessControl, Principal, Role
from ..manager import EngagementManager
from ..schemas.common import utcnow
from ..schemas.events import Event
from ..schemas.scope import RateLimit, RulesOfEngagement, Scope
from ..verify.verifier import VerifyReport
from . import views
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

    cidrs: list[str] = []
    hosts: list[str] = []
    for entry in roe.get("scope_allowlist") or []:
        classified = _classify_target(entry)
        if classified is None:
            continue
        kind, value = classified
        (cidrs if kind == "cidr" else hosts).append(value)

    intensity = str(roe.get("max_intensity") or "recon")
    read_only, tier = _INTENSITY.get(intensity, (True, 0))

    techniques = set(roe.get("allowed_techniques") or [])
    if intensity == "exploit":
        techniques |= {"exploit_confirm", "exploitation"}

    expires_at: datetime | None = None
    window_end = roe.get("window_end")
    if window_end:
        try:
            expires_at = datetime.fromisoformat(str(window_end).replace("Z", "+00:00"))
        except ValueError:
            expires_at = None

    rules = RulesOfEngagement(
        read_only=read_only,
        autonomy_tier=tier,
        authorized_techniques=frozenset(techniques),
        forbidden_tools=frozenset(roe.get("forbidden_tools") or []),
        # Headroom for the verification oracles' rapid differential probing
        # (boolean-blind SQLi fires several http_probes back-to-back).
        default_rate_limit=RateLimit(requests_per_sec=50, burst=20),
    )
    return Scope(
        engagement_id=engagement_id_for(external_id),
        allowed_cidrs=tuple(dict.fromkeys(cidrs)),
        allowed_hosts=tuple(dict.fromkeys(hosts)),
        roe=rules,
        authorized_by=authorized_by,
        signature=signature,
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
        """Bind a signed scope → live engagement (idempotent per id)."""

        eng = self._manager.open(
            scope, self._service, require_signed=require_signed
        )
        self._scopes[scope.engagement_id] = scope
        return eng

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

    # ── operations (real engine work) ──────────────────────────────────────
    def _record_run(self, eid: str, report: Any, *, name: str, role: str) -> None:
        self._runs.setdefault(eid, []).append({
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

    def vuln_scan(self, external_id: str) -> tuple[VerifyReport, MatchReport]:
        """Screen web surfaces, run the accuracy oracles, then correlate CVEs.

        The full safe finding path: WebInquisitor actively screens any web
        targets recon discovered (read-only injection screen), the deterministic
        oracles promote proposed→verified, and the exploitability matcher scores
        + correlates CVEs. Everything scope-enforced and audited.
        """

        from ..netutil import web_targets

        eng = self.engagement(external_id)
        eid = engagement_id_for(external_id)
        web = web_targets(eng.store)
        if web:
            with contextlib.suppress(AttackEngineError):
                web_spec = load_spec(_SPECS_DIR / "web_inquisitor.yaml")
                report = eng.run_agent(web_spec, web)
                self._record_run(eid, report, name="Web Inquisitor", role="offensive")
        # Verify + correlate independently — a single tool/rate hiccup in one
        # oracle degrades that finding, it never sinks the whole scan.
        verify = VerifyReport()
        match = MatchReport()
        with contextlib.suppress(AttackEngineError):
            verify = eng.verify()
        with contextlib.suppress(AttackEngineError):
            match = eng.correlate()
        return verify, match

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
        self, external_id: str, kind: str, targets: list[str] | None = None
    ) -> dict[str, Any]:
        """Start recon ('sense') or 'vuln-scan' on a worker thread.

        Returns immediately with a job record so the HTTP request never blocks on
        a minutes-long, Docker-spawning scan. Progress streams over the event
        queue; poll :meth:`jobs` (or subscribe to the SSE stream) for completion.
        Refuses a second concurrent job for the same engagement.
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
                "ended_at": None, "detail": "",
            }
            self._jobs.setdefault(eid, []).append(job)
        self._emit(eid, "job.started", {"job": job["id"], "kind": kind})
        threading.Thread(
            target=self._run_job, args=(external_id, job, kind, targets or []),
            daemon=True,
        ).start()
        return job

    def _run_job(
        self, external_id: str, job: dict[str, Any], kind: str, targets: list[str]
    ) -> None:
        eid = engagement_id_for(external_id)
        try:
            if kind == "sense":
                self.sense(external_id, targets)
            elif kind == "vuln-scan":
                self.vuln_scan(external_id)
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

    def findings(self, external_id: str) -> list[dict[str, Any]]:
        return [finding_to_json(f) for f in self.engagement(external_id).store.findings()]

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

    def attack_path(self, external_id: str) -> dict[str, Any]:
        return views.build_attack_path(self.assets(external_id), self.findings(external_id))

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
        assets = findings_open = 0
        for eid in open_ids:
            eng = self._manager.get(eid, self._service)
            assets += len(eng.store.assets())
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
            "pending_approvals": 0,
            "model_calls": 0,
            "model_spend": 0,
            "agents": 0,
        }
