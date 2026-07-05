import os
import logging

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware

from orchestration import router as orch_router
from model_gateway import router as model_router
from tool_service import router as tool_router
from sensing import router as sensing_router
from threat_model import router as threat_router
from vuln_loop import router as vuln_router
from agent_runtime import router as agent_router
from reporting import router as report_router
from attack_path import router as attack_router
from red_scope import router as red_scope_router
from auth import router as auth_router, ensure_indexes, seed_admin, get_current_user
from seed import seed_if_empty

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("8pi")

app = FastAPI(title="8pi — Agentic Cybersecurity Platform", version="1.0.0")

# CORS — explicit origins when using cookies with credentials. Wildcard `*` is rejected
# by browsers when allow_credentials=True.
origins_env = os.environ.get("FRONTEND_ORIGINS", "")
allowed = [o.strip() for o in origins_env.split(",") if o.strip()]
if not allowed:
    # dev: fall back to permissive (no credentials so cookies won't be sent cross-origin)
    allowed = ["*"]
    _allow_creds = False
else:
    _allow_creds = True
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed,
    allow_credentials=_allow_creds,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ────────────────────────── public router (no auth) ──────────────────────────
public = APIRouter(prefix="/api")


@public.get("/")
async def root():
    return {"status": "ok", "platform": "8pi", "version": "v1"}


@public.get("/health")
async def health():
    return {"status": "ok", "platform": "8pi", "version": "v1"}


@public.get("/readiness")
async def readiness():
    from db import db as _db
    from fastapi import HTTPException
    try:
        await _db.command("ping")
        return {"status": "ok", "mongo": "up"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"mongo unavailable: {str(e)[:120]}")


public.include_router(auth_router)  # /auth/login, /auth/refresh (public) — protected ones use per-route deps


# ────────────────────────── protected router (JWT required) ──────────────────────────
api = APIRouter(prefix="/api", dependencies=[Depends(get_current_user)])
for r in (orch_router, model_router, tool_router, sensing_router,
          threat_router, vuln_router, agent_router, report_router, attack_router, red_scope_router):
    api.include_router(r)


app.include_router(public)
app.include_router(api)


@app.on_event("startup")
async def _startup():
    try:
        await ensure_indexes()
        seeded = await seed_admin()
        if seeded:
            logger.info("8pi admin ensured (id=%s)", seeded)
    except Exception as e:
        logger.exception("auth setup failed: %s", e)
    try:
        await seed_if_empty()
        logger.info("8pi seed complete")
    except Exception as e:
        logger.exception("seed failed: %s", e)
