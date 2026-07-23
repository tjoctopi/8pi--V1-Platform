"""FastAPI app — the HTTP shell over the engine.

Serves the exact ``/api/*`` contract the 8π console (``frontend/``) already
speaks, backed by the real :class:`~attack_engine.api.adapter.EngineAdapter`.
No Mongo, no external services: users + engagement metadata persist in SQLite
(:class:`~attack_engine.api.store.ShellStore`); scope, findings, gates and the
hash-chained audit log live in the engine.

Wiring status (all driven by the REAL engine):
* auth, engagement lifecycle, RoE draft + signing/test-auth;
* recon (sense), assets, threat-map;
* the autonomous pipeline — vuln-scan (web reasoning loop → oracle graduation →
  verify + correlate), Run Full Attack (``AdversaryCampaign``), per-archetype
  agent runs — all off the request thread as background jobs with live SSE;
* findings, remediate/re-test, CVE cache + refresh;
* attack-path + its live model-generated narrative, and the registered world model;
* human approval gates, audit + chain verify, model gateway + Red Scope copilot,
  report (JSON/HTML/PDF), dashboard stats.
A handful of power-user / custom-agent-lifecycle actions are intentionally not part
of this build (fixed reasoning archetypes, rule #3) and return a clear 501.

Run:  ``uvicorn attack_engine.api.app:app --reload`` (or ``python -m
attack_engine.api.app``). Point the console's ``REACT_APP_BACKEND_URL`` at it.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, NoReturn, cast

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from ..errors import AttackEngineError
from .adapter import EngineAdapter, scope_from_roe
from .auth import (
    get_current_user,
    hash_password,
    make_tokens,
    now_iso,
    public_user,
    require_role,
    seed_admin,
    verify_password,
)
from .store import ShellStore

# ── request models ───────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    email: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str | None = None


class RegisterBody(BaseModel):
    email: str
    password: str
    name: str
    role: str = "operator"


class EngagementCreate(BaseModel):
    name: str
    estate_seeds: list[str] = []
    created_by: str | None = None


class RoeUpdate(BaseModel):
    scope_allowlist: list[str] = []
    scope_denylist: list[str] = []
    allowed_tools: list[str] = []
    forbidden_tools: list[str] = []
    allowed_techniques: list[str] = []
    window_start: str | None = None
    window_end: str | None = None
    max_intensity: str = "recon"


class SignBody(BaseModel):
    signed_by: str


class DenyBody(BaseModel):
    reason: str = "denied by approver"


class InferBody(BaseModel):
    messages: list[dict[str, Any]] = []
    sensitivity: str = "internal"
    route: str | None = None
    purpose: str = "analyst-query"
    task_class: str = "reason"
    engagement_id: str | None = None


class ChatBody(BaseModel):
    message: str
    history: list[dict[str, Any]] = []
    context: dict[str, Any] | None = None


class CommandBody(BaseModel):
    command: str


# ── startup: rehydrate live engagements ─────────────────────────────────────

def _reopen_active_engagements(store: ShellStore, adapter: EngineAdapter) -> None:
    """Re-open previously-active engagements on API start so results reappear after a
    deploy/restart without a manual re-activate. Re-opening rebuilds each engagement's
    KnowledgeStore, which rehydrates its persisted assets/findings from the durable
    backend. Best-effort per engagement — one failure never blocks startup.
    """

    import structlog

    log = structlog.get_logger("api.startup")
    for doc in store.list_engagements():
        if doc.get("status") != "active" or doc.get("archived"):
            continue
        eid = doc["id"]
        roe = doc.get("roe") or {}
        try:
            if roe.get("signature"):
                scope = scope_from_roe(eid, roe, authorized_by=roe.get("signed_by"),
                                       signature=roe.get("signature"))
                adapter.open(scope, require_signed=False)
            elif os.environ.get("AE_ALLOW_TEST_AUTH", "").lower() in ("1", "true", "yes"):
                targets = roe.get("scope_allowlist") or doc.get("estate", {}).get("seeds", [])
                if targets:
                    adapter.open_for_testing(eid, targets)
                else:
                    continue
            else:
                continue
            log.info("engagement rehydrated on startup", engagement=eid,
                     assets=len(adapter.assets(eid)), findings=len(adapter.findings(eid)))
        except Exception as exc:
            log.warning("could not rehydrate engagement", engagement=eid, error=str(exc))


# ── app factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.store = ShellStore(os.environ.get("AE_API_DB", "./data/api_shell.db"))
        app.state.adapter = EngineAdapter()
        seeded = seed_admin(app.state.store)
        if seeded:
            app.state.logger_admin = seeded
        _reopen_active_engagements(app.state.store, app.state.adapter)
        yield
        app.state.store.close()

    app = FastAPI(title="8π Attack Engine API", version="1.0.0", lifespan=lifespan)

    origins = [
        o.strip()
        for o in os.environ.get("AE_API_ORIGINS", "http://localhost:3000").split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def adapter() -> EngineAdapter:  # handler-local accessor for the engine bridge
        return cast(EngineAdapter, app.state.adapter)

    def store() -> ShellStore:
        return cast(ShellStore, app.state.store)

    # ── public ────────────────────────────────────────────────────────────
    public = APIRouter(prefix="/api")

    @public.get("/")
    @public.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "platform": "8pi", "version": "v1"}

    @public.post("/auth/login")
    async def login(body: LoginBody) -> dict[str, Any]:
        user = store().user_by_email(body.email)
        if not user or not verify_password(body.password, user["pw_hash"]):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        store().touch_login(user["id"], now_iso())
        return {"user": public_user(user), **make_tokens(user)}

    @public.post("/auth/refresh")
    async def refresh(body: RefreshBody) -> dict[str, Any]:
        import jwt as _jwt

        from .auth import decode

        raw = body.refresh_token
        if not raw:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no refresh token")
        try:
            claims = decode(raw)
        except _jwt.PyJWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token") from None
        if claims.get("type") != "refresh":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
        user = store().user_by_id(claims.get("sub", ""))
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user gone")
        return {"user": public_user(user), **make_tokens(user)}

    # ── protected ───────────────────────────────────────────────────────────
    api = APIRouter(prefix="/api", dependencies=[Depends(get_current_user)])

    @api.get("/auth/me")
    async def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        return {"user": public_user(user)}

    @api.post("/auth/logout")
    async def logout() -> dict[str, Any]:
        return {"ok": True}

    @api.get("/auth/users")
    async def list_users(_: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
        return {"users": [public_user(u) for u in store().list_users()]}

    @api.post("/auth/users")
    async def create_user(
        body: RegisterBody, _: dict[str, Any] = Depends(require_role("admin"))
    ) -> dict[str, Any]:
        if store().user_by_email(body.email):
            raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
        uid = f"u-{secrets.token_hex(8)}"
        rec = {
            "id": uid, "email": body.email, "name": body.name, "role": body.role,
            "pw_hash": hash_password(body.password), "created_at": now_iso(),
            "last_login": None,
        }
        store().create_user(rec)
        return {"user": public_user(rec)}

    @api.delete("/auth/users/{uid}")
    async def delete_user(
        uid: str, user: dict[str, Any] = Depends(require_role("admin"))
    ) -> dict[str, Any]:
        if uid == user["id"]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete yourself")
        store().delete_user(uid)
        return {"ok": True}

    # ── engagement lifecycle ─────────────────────────────────────────────────
    def _counts(doc: dict[str, Any]) -> dict[str, Any]:
        eid = doc["id"]
        a = f = p = inv = runs = mc = 0
        if doc["status"] == "active" and adapter().is_open(eid):
            try:
                a = len(adapter().assets(eid))
                f = len(adapter().findings(eid))
                p = adapter().pending_approvals(eid)
                inv = len(adapter().invocations(eid))
                runs = len(adapter().agent_runs(eid))
                mc = len(adapter().model_calls(eid))
            except AttackEngineError:
                pass
        return {"assets": a, "findings": f, "invocations": inv,
                "pending_approvals": p, "agent_runs": runs, "model_calls": mc}

    def _list_item(doc: dict[str, Any]) -> dict[str, Any]:
        c = _counts(doc)
        return {
            "id": doc["id"], "name": doc["name"], "status": doc["status"],
            "halted": doc["halted"], "archived": doc["archived"],
            "created_at": doc["created_at"], "created_by": doc.get("created_by"),
            "closed_at": doc.get("closed_at"),
            "roe_signed": bool(doc["roe"].get("signature")),
            "max_intensity": doc["roe"].get("max_intensity", "recon"),
            "estate": doc.get("estate", {}),
            "counts": {"assets": c["assets"], "findings": c["findings"],
                       "pending_approvals": c["pending_approvals"]},
        }

    @api.get("/stats")
    async def stats() -> dict[str, Any]:
        base = adapter().stats()
        engs = store().list_engagements()
        by_status: dict[str, int] = {}
        for d in engs:
            by_status[d["status"]] = by_status.get(d["status"], 0) + 1
        base["engagements"] = len(engs)
        base["engagements_by_status"] = by_status
        return base

    @api.get("/engagements")
    async def list_engagements(include_archived: int = 0) -> dict[str, Any]:
        docs = store().list_engagements()
        if not include_archived:
            docs = [d for d in docs if not d.get("archived")]
        return {"engagements": [_list_item(d) for d in docs]}

    @api.post("/engagements")
    async def create_engagement(
        body: EngagementCreate, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        eid = f"eng-{secrets.token_hex(6)}"
        doc = {
            "id": eid, "name": body.name, "status": "draft",
            "halted": False, "archived": False,
            "created_by": body.created_by or user["email"],
            "created_at": now_iso(), "closed_at": None,
            "estate": {"id": f"est-{secrets.token_hex(4)}", "name": body.name,
                       "seeds": body.estate_seeds},
            "roe": {
                "id": f"roe-{secrets.token_hex(4)}", "version": 1,
                "scope_allowlist": list(body.estate_seeds), "scope_denylist": [],
                "allowed_tools": ["nmap"], "allowed_techniques": [],
                "max_intensity": "recon", "window_start": None, "window_end": None,
                "signature": None, "signed_by": None, "signed_at": None,
            },
        }
        store().save_engagement(doc)
        return _list_item(doc)

    def _load(eid: str) -> dict[str, Any]:
        doc = store().get_engagement(eid)
        if not doc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        return doc

    @api.get("/engagements/{eid}")
    async def get_engagement(eid: str) -> dict[str, Any]:
        doc = _load(eid)
        return {"engagement": _list_item(doc), "roe": doc["roe"], "counts": _counts(doc)}

    @api.put("/engagements/{eid}/roe")
    async def update_roe(
        eid: str, body: RoeUpdate, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        if doc["roe"].get("signature"):
            raise HTTPException(status.HTTP_409_CONFLICT, "signed RoE is immutable")
        doc["roe"].update({
            "scope_allowlist": body.scope_allowlist, "scope_denylist": body.scope_denylist,
            "allowed_tools": body.allowed_tools, "forbidden_tools": body.forbidden_tools,
            "allowed_techniques": body.allowed_techniques,
            "max_intensity": body.max_intensity, "window_start": body.window_start,
            "window_end": body.window_end, "version": doc["roe"].get("version", 1) + 1,
        })
        store().save_engagement(doc)
        adapter().record_governance(
            eid, actor=user["email"], action="roe.updated",
            payload={"version": doc["roe"]["version"],
                     "max_intensity": doc["roe"]["max_intensity"],
                     "scope_targets": len(doc["roe"]["scope_allowlist"]),
                     "allowed_tools": doc["roe"]["allowed_tools"]},
        )
        return dict(doc["roe"])

    @api.post("/engagements/{eid}/roe/sign")
    async def sign_roe(
        eid: str, body: SignBody, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        roe: dict[str, Any] = doc["roe"]
        roe["signed_by"] = body.signed_by
        roe["signed_at"] = now_iso()
        roe["signature"] = secrets.token_hex(24)  # binds the human authorization
        store().save_engagement(doc)
        adapter().record_governance(
            eid, actor=user["email"], action="roe.signed",
            payload={"signed_by": body.signed_by, "version": roe.get("version", 1),
                     "signature_prefix": roe["signature"][:12]},
        )
        return roe

    @api.post("/engagements/{eid}/activate")
    async def activate(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        roe = doc["roe"]
        if not roe.get("signature"):
            raise HTTPException(status.HTTP_412_PRECONDITION_FAILED, "RoE must be signed first")
        scope = scope_from_roe(
            eid, roe, authorized_by=roe.get("signed_by"), signature=roe["signature"]
        )
        try:
            adapter().open(scope)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        doc["status"] = "active"
        doc["halted"] = False
        store().save_engagement(doc)
        adapter().record_governance(
            eid, actor=user["email"], action="engagement.activated",
            payload={"max_intensity": roe.get("max_intensity"),
                     "signed_by": roe.get("signed_by")},
        )
        return _list_item(doc)

    @api.post("/engagements/{eid}/activate-test")
    async def activate_test(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """One-click activate for TESTING — opens the engagement without signing.

        Only works when the deployment set ``AE_ALLOW_TEST_AUTH=true`` (a testing
        deployment); the engine refuses the test authorization otherwise. Builds a
        ``Scope.for_testing`` from the RoE's scope_allowlist so you can drive the
        platform end-to-end from the console without the sign/authorization step.
        """

        if not adapter().engine.settings.allow_test_authorization:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "test authorization is not enabled on this deployment "
                "(set AE_ALLOW_TEST_AUTH=true on a testing deployment)",
            )
        doc = _load(eid)
        targets = list(doc["roe"].get("scope_allowlist") or [])
        if not targets:
            raise HTTPException(
                status.HTTP_412_PRECONDITION_FAILED,
                "RoE needs a scope_allowlist target to test against",
            )
        try:
            adapter().open_for_testing(eid, targets)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        doc["status"] = "active"
        doc["halted"] = False
        doc["roe"]["test_authorization"] = True  # mark it as a test run in the record
        store().save_engagement(doc)
        adapter().record_governance(
            eid, actor=user["email"], action="engagement.activated",
            payload={"test_authorization": True, "targets": len(targets)},
        )
        return _list_item(doc)

    @api.post("/engagements/{eid}/pause")
    async def pause(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["status"] = "paused"
        store().save_engagement(doc)
        adapter().record_governance(eid, actor=user["email"], action="engagement.paused")
        return _list_item(doc)

    @api.post("/engagements/{eid}/close")
    async def close(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        adapter().record_governance(eid, actor=user["email"], action="engagement.closed")
        if adapter().is_open(eid):
            adapter().close(eid)
        doc["status"] = "closed"
        doc["closed_at"] = now_iso()
        store().save_engagement(doc)
        return _list_item(doc)

    @api.post("/engagements/{eid}/halt")
    async def halt(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        if adapter().is_open(eid):
            adapter().halt(eid, by=user["email"])
        doc["halted"] = True
        store().save_engagement(doc)
        adapter().record_governance(
            eid, actor=user["email"], action="engagement.halted",
            payload={"reason": "operator kill switch"},
        )
        return {"halted": True}

    @api.post("/engagements/{eid}/resume")
    async def resume(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        # A tripped kill switch is a hard stop; resuming re-binds a fresh handle.
        if doc["halted"] and doc["status"] == "active":
            with contextlib.suppress(KeyError, AttackEngineError):
                adapter().resume(eid)
        doc["halted"] = False
        store().save_engagement(doc)
        adapter().record_governance(eid, actor=user["email"], action="engagement.resumed")
        return {"halted": False}

    @api.post("/engagements/{eid}/archive")
    async def archive(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["archived"] = True
        store().save_engagement(doc)
        adapter().record_governance(eid, actor=user["email"], action="engagement.archived")
        return {"archived": True}

    @api.post("/engagements/{eid}/unarchive")
    async def unarchive(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["archived"] = False
        store().save_engagement(doc)
        adapter().record_governance(eid, actor=user["email"], action="engagement.unarchived")
        return {"archived": False}

    @api.post("/engagements/{eid}/purge")
    async def purge(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Clear an engagement's RESULTS (assets/findings/tool-runs/agent-runs) —
        durable + in-memory — keeping the engagement, RoE, and audit chain."""

        _load(eid)
        return adapter().purge_engagement(eid, actor=user["email"])

    @api.delete("/engagements/{eid}")
    async def delete_engagement(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Delete an engagement and its persisted results. The immutable audit chain
        is preserved (a ``engagement.deleted`` entry records the deletion)."""

        _load(eid)
        result = adapter().delete_engagement(eid, actor=user["email"])
        store().delete_engagement(eid)  # shell metadata keyed by the external id
        return result

    # ── recon / assets ────────────────────────────────────────────────────
    def _require_open(eid: str) -> None:
        _load(eid)
        if not adapter().is_open(eid):
            raise HTTPException(status.HTTP_412_PRECONDITION_FAILED,
                                "engagement is not active — activate it first")

    @api.post("/engagements/{eid}/sense")
    async def sense(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        _require_open(eid)
        targets = doc["roe"].get("scope_allowlist") or doc.get("estate", {}).get("seeds", [])
        try:
            job = adapter().start_job(eid, "sense", targets)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "sense"}

    @api.get("/engagements/{eid}/assets")
    async def assets(eid: str) -> dict[str, Any]:
        _require_open(eid)
        return {"assets": adapter().assets(eid)}

    # ── vuln loop / findings ──────────────────────────────────────────────
    @api.post("/engagements/{eid}/vuln-scan")
    async def vuln_scan(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        _require_open(eid)
        try:
            job = adapter().start_job(eid, "vuln-scan")
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "vuln-scan"}

    @api.post("/engagements/{eid}/campaign")
    async def campaign(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Run the full autonomous kill chain (recon → web → identity → objective).

        Drives the real :class:`AdversaryCampaign` on a background worker (Docker- and
        model-spawning, minutes-long) so the request never blocks. Progress streams over
        the engagement SSE channel; poll ``/jobs`` for completion. Scope-enforced, gated,
        and audited by the engine.
        """

        doc = _load(eid)
        _require_open(eid)
        targets = doc["roe"].get("scope_allowlist") or doc.get("estate", {}).get("seeds", [])
        try:
            job = adapter().start_job(eid, "campaign", targets)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "campaign"}

    @api.get("/engagements/{eid}/jobs")
    async def jobs(eid: str) -> dict[str, Any]:
        _load(eid)
        return {"jobs": adapter().jobs(eid) if adapter().is_open(eid) else []}

    @api.get("/engagements/{eid}/events")
    async def events(eid: str) -> StreamingResponse:
        _load(eid)
        return StreamingResponse(
            adapter().event_stream(eid), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @api.get("/engagements/{eid}/findings")
    async def findings(eid: str) -> dict[str, Any]:
        _require_open(eid)
        return {"findings": adapter().findings(eid)}

    # ── audit ──────────────────────────────────────────────────────────────
    @api.get("/engagements/{eid}/audit")
    async def audit(
        eid: str, limit: int = 500, event_type: str | None = None, actor: str | None = None
    ) -> dict[str, Any]:
        _load(eid)
        return {"events": adapter().audit_events(
            eid, limit=limit, event_type=event_type, actor=actor)}

    @api.get("/engagements/{eid}/audit/verify")
    async def audit_verify(eid: str) -> dict[str, Any]:
        _load(eid)
        return adapter().audit_verify(eid)

    # ── tool / agent catalog (real registry data) ───────────────────────────
    @api.get("/tools")
    async def tools() -> dict[str, Any]:
        registry = adapter().engine.registry
        names = sorted(registry.names()) if hasattr(registry, "names") else []
        out = []
        for n in names:
            licensed = False
            with contextlib.suppress(Exception):
                licensed = bool(getattr(registry.resolve(n), "licensed", False))
            out.append({
                "tool_id": n, "name": n, "class": "recon", "min_intensity": "recon",
                # licensed (commercial) tools show locked until RoE enables them
                "license_verified": not licensed, "licensed": licensed,
                "category": "recon", "description": "", "params": [],
                "installed": True, "effective_mode": "real",
            })
        return {"tools": out, "tool_mode": "real"}

    @api.get("/tools/availability")
    async def tool_availability() -> dict[str, Any]:
        return {"mode": "real", "tools": {}}

    @api.get("/cve-cache")
    async def cve_cache() -> dict[str, Any]:
        return {"cves": adapter().cve_cache()}

    @api.get("/engagements/{eid}/invocations")
    async def invocations(eid: str, limit: int = 200) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"invocations": []}
        return {"invocations": adapter().invocations(eid, limit=limit)}

    @api.get("/agents")
    async def agents() -> dict[str, Any]:
        # The engine's fixed archetypes presented as the built-in agent catalog.
        catalog = [
            ("surface-mapper", "Surface Mapper", "recon"),
            ("web-inquisitor", "Web Inquisitor", "offensive"),
            ("exploit-confirmer", "Exploit Confirmer", "offensive"),
            ("converter", "Converter / Remediator", "defensive"),
        ]
        return {"agents": [
            {"id": aid, "name": name, "version": "1.0.0", "role": role,
             "promotion_state": "authorized", "last_sandbox_pass": now_iso(),
             "origin": "built-in", "created_at": now_iso(),
             "spec": {"tools": [], "guardrails": {"max_intensity": "safe-active"}}}
            for aid, name, role in catalog
        ]}

    @api.get("/sandbox-targets")
    async def sandbox_targets() -> dict[str, Any]:
        return {"targets": [
            {"id": "range-juice", "label": "Juice Shop (10.5.0.10)", "profile": "web"},
            {"id": "range-dvwa", "label": "DVWA (10.5.0.11)", "profile": "web"},
            {"id": "range-msf", "label": "Metasploitable (10.5.0.12)", "profile": "host"},
        ]}

    @api.get("/engagements/{eid}/agent-runs")
    async def agent_runs(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"runs": []}
        return {"runs": adapter().agent_runs(eid)}

    @api.get("/engagements/{eid}/approvals")
    async def approvals(eid: str, status: str | None = None) -> dict[str, Any]:
        _load(eid)
        return {"approvals": adapter().approvals(eid, status)}

    @api.post("/approvals/{aid}/approve")
    async def approve(
        aid: str, user: dict[str, Any] = Depends(require_role("approver"))
    ) -> dict[str, Any]:
        ok = adapter().resolve_approval(aid, approved=True, approver=user["email"])
        if not ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "approval is no longer pending (already resolved or timed out)",
            )
        return {"ok": True, "decision": "approved"}

    @api.post("/approvals/{aid}/deny")
    async def deny(
        aid: str,
        body: DenyBody | None = None,
        user: dict[str, Any] = Depends(require_role("approver")),
    ) -> dict[str, Any]:
        reason = (body.reason if body else None) or "denied by approver"
        ok = adapter().resolve_approval(
            aid, approved=False, approver=user["email"], reason=reason
        )
        if not ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "approval is no longer pending (already resolved or timed out)",
            )
        return {"ok": True, "decision": "denied"}

    @api.get("/model/routes")
    async def model_routes() -> dict[str, Any]:
        gw = adapter().engine.gateway
        return {"routes": [
            {"id": "frontier", "provider": gw.provider_name, "model": "frontier",
             "kind": "hosted", "boundary": "external", "cost_per_1k": 0,
             "status": "live", "description": "BYOM frontier tier"},
            {"id": "local", "provider": gw.provider_name, "model": "local",
             "kind": "local", "boundary": "internal", "cost_per_1k": 0,
             "status": "live", "description": "BYOM local tier"},
        ]}

    @api.get("/model/calls")
    async def model_calls(
        engagement_id: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        return {"calls": adapter().model_calls(engagement_id)[:limit]}

    @api.get("/red-scope")
    async def red_scope() -> dict[str, Any]:
        halted: list[dict[str, Any]] = []
        crit: list[dict[str, Any]] = []
        approvals: list[dict[str, Any]] = []
        for d in store().list_engagements():
            if d.get("halted"):
                halted.append({"id": d["id"], "name": d["name"], "status": d["status"]})
            if d["status"] == "active" and adapter().is_open(d["id"]):
                for ap in adapter().approvals(d["id"], status="pending"):
                    approvals.append({**ap, "engagement_id": d["id"],
                                      "engagement_name": d["name"]})
                for f in adapter().findings(d["id"]):
                    if f["severity"] in ("crit", "high") and f["exploitability"] in (
                        "reachable", "confirmed"
                    ):
                        crit.append({**f, "engagement_id": d["id"],
                                     "engagement_name": d["name"],
                                     "target": f.get("asset_id")})
        return {"halted_engagements": halted, "critical_findings": crit,
                "exploit_approvals": approvals,
                "counts": {"halted": len(halted), "critical_findings": len(crit),
                           "exploit_approvals": len(approvals)}}

    @api.get("/engagements/{eid}/threat-map")
    async def threat_map(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"nodes": [], "edges": [], "risk": [], "layers": []}
        return adapter().threat_map(eid)

    @api.get("/engagements/{eid}/attack-tree")
    async def attack_tree(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"phases": [], "nodes": [], "edges": [], "summary": {}}
        return adapter().attack_tree(eid)

    @api.get("/engagements/{eid}/attack-path")
    async def attack_path(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"paths": [], "points": [], "arcs": [], "entry_points": [],
                    "crown_jewels": [], "continents": [], "layer_stats": [],
                    "stats": {"entry": 0, "crown": 0, "pivot": 0, "paths": 0}}
        return adapter().attack_path(eid)

    @api.get("/engagements/{eid}/world-model")
    async def world_model(eid: str) -> dict[str, Any]:
        _load(eid)
        return adapter().world_model_view(eid)

    @api.get("/engagements/{eid}/campaign-status")
    async def campaign_status(eid: str) -> dict[str, Any]:
        _load(eid)
        return adapter().campaign_status(eid)

    @api.get("/engagements/{eid}/authorization")
    async def authorization(eid: str) -> dict[str, Any]:
        """Rules-of-engagement control room: techniques/tools/actions →
        autonomous / gated / denied, from the signed RoE. Operators change status by
        editing the RoE (PUT /roe) — the toggles the console shows."""

        doc = _load(eid)
        return adapter().authorization_view(eid, doc.get("roe"))

    @api.post("/engagements/{eid}/chains/{chain_id}/execute")
    async def execute_chain(
        eid: str, chain_id: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Run the attack along a composed chain (confirm rungs → open a session if a
        foothold rung confirms) — as a governed background job (poll ``/jobs`` kind
        ``chain-exec``, watch ``/sessions`` + ``/attack-path``)."""

        _require_open(eid)
        try:
            job = adapter().start_job(eid, "chain-exec", ref=chain_id)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "chain-exec"}

    # ── offensive C2 / live footholds ────────────────────────────────────────
    @api.get("/engagements/{eid}/sessions")
    async def sessions(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"sessions": [], "candidates": []}
        return adapter().sessions(eid)

    @api.post("/engagements/{eid}/findings/{fid}/establish-foothold")
    async def establish_foothold(
        eid: str, fid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Open a live, governed C2 session over a confirmed web RCE — as a job.

        Runs off the request thread because establishing a foothold is a high-impact
        gated action: under a real scope it parks for human approval (poll ``/jobs``
        kind ``foothold`` + watch ``/sessions``); under test-auth it completes fast.
        """

        _require_open(eid)
        try:
            job = adapter().start_job(eid, "foothold", ref=fid)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "foothold"}

    @api.post("/engagements/{eid}/sessions/{sid}/command")
    async def session_command(
        eid: str, sid: str, body: CommandBody,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        _require_open(eid)
        if not body.command.strip():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "command required")
        try:
            return adapter().session_command(eid, sid, body.command, actor=user["email"])
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @api.post("/engagements/{eid}/sessions/{sid}/teardown")
    async def teardown_session(
        eid: str, sid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        _require_open(eid)
        try:
            return adapter().teardown_session(eid, sid, actor=user["email"])
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @api.get("/engagements/{eid}/attack-path/stream")
    async def attack_path_stream(
        eid: str, user: dict[str, Any] = Depends(get_current_user)
    ) -> StreamingResponse:
        """SSE narrative of the breach route, generated live by the BYOM gateway.

        Streams the model's reasoning over the engine's real findings as ``delta``
        events, then a final ``done`` event with the route + usage. Honest empty
        notice when there is nothing to narrate yet.
        """

        _load(eid)

        async def _gen() -> AsyncIterator[str]:
            yield "retry: 3000\n\n"
            try:
                result = await run_in_threadpool(
                    adapter().attack_path_narrative, eid, actor=user["email"]
                )
            except AttackEngineError as exc:
                yield f"data: {json.dumps({'done': True, 'error': str(exc)})}\n\n"
                return
            text = result.get("text") or ""
            done: dict[str, Any] = {"done": True, "route": result.get("route"),
                                    "usage": result.get("usage")}
            if not text:
                done["empty"] = True
                yield f"data: {json.dumps(done)}\n\n"
                return
            # chunk the model output into deltas so the console renders it live
            for i in range(0, len(text), 24):
                yield f"data: {json.dumps({'delta': text[i:i + 24]})}\n\n"
            yield f"data: {json.dumps(done)}\n\n"

        return StreamingResponse(
            _gen(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def _build_report(eid: str) -> dict[str, Any]:
        doc = _load(eid)
        findings = adapter().findings(eid) if adapter().is_open(eid) else []
        summary = (
            adapter().report_summary(eid) if adapter().is_open(eid)
            else {"assets": 0, "findings_total": 0, "findings_open_by_severity": {},
                  "findings_closed": 0, "agent_runs": 0, "audit_events": 0,
                  "audit_chain_valid": True}
        )
        return {"generated_at": now_iso(), "engagement": _list_item(doc),
                "roe": doc["roe"], "summary": summary, "findings": findings}

    @api.get("/engagements/{eid}/report")
    async def report(eid: str) -> dict[str, Any]:
        return _build_report(eid)

    @api.get("/engagements/{eid}/report.html")
    async def report_html(eid: str) -> HTMLResponse:
        from .report_html import render_report_html

        return HTMLResponse(render_report_html(_build_report(eid)))

    @api.get("/engagements/{eid}/report.pdf")
    async def report_pdf(eid: str) -> Response:
        from .report_html import render_report_html

        html = render_report_html(_build_report(eid))
        try:
            from weasyprint import HTML as _WeasyHTML  # optional dep
        except ImportError as exc:
            raise HTTPException(
                status.HTTP_501_NOT_IMPLEMENTED,
                "PDF export requires the optional 'weasyprint' package "
                "(not installed on this deployment) — use the HTML export instead.",
            ) from exc
        pdf = _WeasyHTML(string=html).write_pdf()
        name = _load(eid)["name"].replace(" ", "_")
        return Response(
            content=pdf, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="8pi-report-{name}.pdf"'},
        )

    @api.get("/engagements/{eid}/assets/{aid}")
    async def asset_detail(eid: str, aid: str) -> dict[str, Any]:
        _require_open(eid)
        detail = adapter().asset_detail(eid, aid)
        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        return detail

    # ── actions intentionally not part of this build: fail cleanly (501) with an
    #    honest reason, never a silent 404. The platform runs fixed reasoning
    #    archetypes (rule #3: roles, not user-created agent clones), so there is no
    #    custom-agent create/promote/sandbox lifecycle, and direct ad-hoc tool
    #    execution is deliberately not exposed (tools run inside governed agent runs).
    _NOT_WIRED = (
        "Not part of this build: the platform runs fixed reasoning archetypes and "
        "governed agent/campaign runs — there is no custom-agent lifecycle or ad-hoc "
        "direct tool execution. Use Run Full Attack / Run Agent / the RoE tool allowlist."
    )

    def _unavailable() -> NoReturn:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, _NOT_WIRED)

    @api.post("/findings/{fid}/remediate")
    async def remediate(
        fid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        try:
            return adapter().remediate_finding(fid, actor=user["email"])
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    @api.post("/findings/{fid}/retest")
    async def retest(
        fid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        try:
            return adapter().retest_finding(fid, actor=user["email"])
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    @api.post("/engagements/{eid}/refresh-cve")
    async def refresh_cve(
        eid: str, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        _load(eid)
        return adapter().refresh_cve(eid, actor=user["email"])

    @api.post("/tools/{tool_id}/run")
    async def run_tool(tool_id: str) -> dict[str, Any]:
        _unavailable()

    @api.get("/invocations/{inv_id}/raw")
    async def invocation_raw(inv_id: str) -> dict[str, Any]:
        detail = adapter().invocation_raw(inv_id)
        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "invocation not found")
        return detail

    @api.post("/agents")
    async def create_agent() -> dict[str, Any]:
        _unavailable()

    @api.post("/agents/{aid}/promote")
    async def promote_agent(aid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/agents/{aid}/sandbox-run")
    async def sandbox_run(aid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/engagements/{eid}/agents/{aid}/run")
    async def run_agent(
        eid: str, aid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        """Dispatch a built-in archetype to its real specialist op as a background job.

        Recon/web archetypes are Docker- and model-spawning (minutes-long), so this
        runs off the request thread like sense/vuln-scan — poll ``/jobs`` (kind
        ``agent-run``) or watch the SSE stream for completion.
        """

        _require_open(eid)
        try:
            job = adapter().start_job(eid, "agent-run", agent_id=aid)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return {"job_id": job["id"], "status": job["status"], "kind": "agent-run"}

    @api.get("/agent-runs/{rid}")
    async def agent_run(rid: str) -> dict[str, Any]:
        detail = adapter().agent_run(rid)
        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "agent run not found")
        return detail

    @api.post("/model/infer")
    async def model_infer(
        body: InferBody, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        if not body.messages:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "messages required")
        try:
            return adapter().model_infer(
                messages=body.messages, sensitivity=body.sensitivity,
                route=body.route, actor=user["email"],
                engagement_id=body.engagement_id,
            )
        except AttackEngineError as exc:
            return {"error": str(exc), "route": body.route or "policy-routed"}

    @api.post("/red-scope/chat")
    async def red_scope_chat(
        body: ChatBody, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        try:
            return adapter().red_scope_chat(
                message=body.message, history=body.history, actor=user["email"]
            )
        except AttackEngineError as exc:
            return {"reply": f"(model gateway unavailable: {exc})"}

    @api.post("/red-scope/agents")
    async def red_scope_save(
        body: dict[str, Any], user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        return adapter().save_red_scope_agent(body, actor=user["email"])

    app.include_router(public)
    app.include_router(api)
    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AE_API_PORT", "8000")))
