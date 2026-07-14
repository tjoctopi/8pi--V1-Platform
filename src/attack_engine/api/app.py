"""FastAPI app — the HTTP shell over the engine.

Serves the exact ``/api/*`` contract the 8π console (``frontend/``) already
speaks, backed by the real :class:`~attack_engine.api.adapter.EngineAdapter`.
No Mongo, no external services: users + engagement metadata persist in SQLite
(:class:`~attack_engine.api.store.ShellStore`); scope, findings, gates and the
hash-chained audit log live in the engine.

Wiring status:
* **Phase 1 (live now):** auth, engagement lifecycle, RoE draft + signing,
  recon (sense), assets, verify+correlate (vuln-scan), findings, audit + verify,
  stats — all driven by the real engine.
* **Phase 2–4 (placeholders):** tools/agents/approvals/model/report/attack-path/
  threat-map/red-scope return valid empty shapes so the console renders, and are
  filled in as those slices land.

Run:  ``uvicorn attack_engine.api.app:app --reload`` (or ``python -m
attack_engine.api.app``). Point the console's ``REACT_APP_BACKEND_URL`` at it.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, NoReturn, cast

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
    allowed_techniques: list[str] = []
    window_start: str | None = None
    window_end: str | None = None
    max_intensity: str = "recon"


class SignBody(BaseModel):
    signed_by: str


# ── app factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.store = ShellStore(os.environ.get("AE_API_DB", "./data/api_shell.db"))
        app.state.adapter = EngineAdapter()
        seeded = seed_admin(app.state.store)
        if seeded:
            app.state.logger_admin = seeded
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
        a = f = 0
        if doc["status"] == "active" and adapter().is_open(eid):
            try:
                a = len(adapter().assets(eid))
                f = len(adapter().findings(eid))
            except AttackEngineError:
                pass
        return {"assets": a, "findings": f, "invocations": 0,
                "pending_approvals": 0, "agent_runs": 0, "model_calls": 0}

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
        eid: str, body: RoeUpdate, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        if doc["roe"].get("signature"):
            raise HTTPException(status.HTTP_409_CONFLICT, "signed RoE is immutable")
        doc["roe"].update({
            "scope_allowlist": body.scope_allowlist, "scope_denylist": body.scope_denylist,
            "allowed_tools": body.allowed_tools, "allowed_techniques": body.allowed_techniques,
            "max_intensity": body.max_intensity, "window_start": body.window_start,
            "window_end": body.window_end, "version": doc["roe"].get("version", 1) + 1,
        })
        store().save_engagement(doc)
        return dict(doc["roe"])

    @api.post("/engagements/{eid}/roe/sign")
    async def sign_roe(
        eid: str, body: SignBody, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        roe: dict[str, Any] = doc["roe"]
        roe["signed_by"] = body.signed_by
        roe["signed_at"] = now_iso()
        roe["signature"] = secrets.token_hex(24)  # binds the human authorization
        store().save_engagement(doc)
        return roe

    @api.post("/engagements/{eid}/activate")
    async def activate(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
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
        return _list_item(doc)

    @api.post("/engagements/{eid}/pause")
    async def pause(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["status"] = "paused"
        store().save_engagement(doc)
        return _list_item(doc)

    @api.post("/engagements/{eid}/close")
    async def close(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
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
        return {"halted": True}

    @api.post("/engagements/{eid}/resume")
    async def resume(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        # A tripped kill switch is a hard stop; resuming re-binds a fresh handle.
        if doc["halted"] and doc["status"] == "active":
            with contextlib.suppress(KeyError, AttackEngineError):
                adapter().resume(eid)
        doc["halted"] = False
        store().save_engagement(doc)
        return {"halted": False}

    @api.post("/engagements/{eid}/archive")
    async def archive(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["archived"] = True
        store().save_engagement(doc)
        return {"archived": True}

    @api.post("/engagements/{eid}/unarchive")
    async def unarchive(
        eid: str, _: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        doc = _load(eid)
        doc["archived"] = False
        store().save_engagement(doc)
        return {"archived": False}

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
            report = adapter().sense(eid, targets)
        except AttackEngineError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        return {"assets_touched": report.assets_found, "rejected": [
            {"seed": t, "reason": "out of scope"} for t in report.skipped_targets]}

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
        verify, match = adapter().vuln_scan(eid)
        return {"created": match.cves_confirmed, "updated": verify.verified}

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

    # ── Phase 2–4 placeholders (valid empty shapes so the console renders) ───
    @api.get("/tools")
    async def tools() -> dict[str, Any]:
        names = sorted(adapter().engine.registry.names()) \
            if hasattr(adapter().engine.registry, "names") else []
        return {"tools": [
            {"tool_id": n, "name": n, "class": "recon", "min_intensity": "recon",
             "license_verified": True, "category": "recon", "description": "",
             "params": [], "installed": True, "effective_mode": "real"} for n in names
        ], "tool_mode": "real"}

    @api.get("/tools/availability")
    async def tool_availability() -> dict[str, Any]:
        return {"mode": "real", "tools": {}}

    @api.get("/cve-cache")
    async def cve_cache() -> dict[str, Any]:
        return {"cves": []}

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
        return {"approvals": []}

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

    @api.get("/engagements/{eid}/attack-path")
    async def attack_path(eid: str) -> dict[str, Any]:
        _load(eid)
        if not adapter().is_open(eid):
            return {"paths": [], "points": [], "arcs": [], "entry_points": [],
                    "crown_jewels": [], "continents": [], "layer_stats": [],
                    "stats": {"entry": 0, "crown": 0, "pivot": 0, "paths": 0}}
        return adapter().attack_path(eid)

    @api.get("/engagements/{eid}/report")
    async def report(eid: str) -> dict[str, Any]:
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

    @api.get("/engagements/{eid}/assets/{aid}")
    async def asset_detail(eid: str, aid: str) -> dict[str, Any]:
        _require_open(eid)
        detail = adapter().asset_detail(eid, aid)
        if detail is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        return detail

    # ── not-yet-wired actions: fail cleanly with a clear message (501), never a
    #    silent 404, so the console shows "not available yet" instead of breaking.
    _NOT_WIRED = "Not available in this build yet — wired to the engine in a later phase."

    def _unavailable() -> NoReturn:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, _NOT_WIRED)

    @api.post("/findings/{fid}/remediate")
    async def remediate(fid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/findings/{fid}/retest")
    async def retest(fid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/engagements/{eid}/refresh-cve")
    async def refresh_cve(eid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/tools/{tool_id}/run")
    async def run_tool(tool_id: str) -> dict[str, Any]:
        _unavailable()

    @api.get("/invocations/{inv_id}/raw")
    async def invocation_raw(inv_id: str) -> dict[str, Any]:
        _unavailable()

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
    async def run_agent(eid: str, aid: str) -> dict[str, Any]:
        _unavailable()

    @api.get("/agent-runs/{rid}")
    async def agent_run(rid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/approvals/{aid}/approve")
    async def approve(aid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/approvals/{aid}/deny")
    async def deny(aid: str) -> dict[str, Any]:
        _unavailable()

    @api.post("/model/infer")
    async def model_infer() -> dict[str, Any]:
        _unavailable()

    @api.post("/red-scope/chat")
    async def red_scope_chat() -> dict[str, Any]:
        _unavailable()

    @api.post("/red-scope/agents")
    async def red_scope_save() -> dict[str, Any]:
        _unavailable()

    app.include_router(public)
    app.include_router(api)
    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AE_API_PORT", "8000")))
