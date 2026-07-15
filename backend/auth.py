"""JWT authentication for 8pi v1.

Roles (highest → lowest):
  - admin    : superuser (user management + everything below)
  - approver : approve/deny exploit gates + everything an operator can do
  - operator : drive the pipeline (RoE, sensing, run tools, run agents)
  - viewer   : read-only access to engagements, findings, reports

Public endpoints (no auth): /api/auth/login, /api/auth/refresh, /api/health,
/api/readiness, /api/. All other /api/* routes require a valid JWT.

Tokens:
  - Access token  : 12h (encodes sub=user_id, email, role)
  - Refresh token : 7d  (rotates access tokens; opaque to app logic)

Transport:
  - Preferred    : Authorization: Bearer <token>
  - Fallback     : access_token httpOnly cookie (for browsers)
  - SSE fallback : ?token=<token> query param (EventSource can't set headers)
"""
import os
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Body, status
from pydantic import BaseModel, EmailStr, Field

from db import db
from pymongo.errors import DuplicateKeyError
from store import now_iso

ROLES = ("admin", "approver", "operator", "viewer")
ROLE_RANK = {r: i for i, r in enumerate(reversed(ROLES))}  # admin=3 > approver=2 > operator=1 > viewer=0
JWT_ALG = "HS256"
ACCESS_TTL_MIN = 12 * 60  # 12h
REFRESH_TTL_DAYS = 7
LOCKOUT_FAIL_LIMIT = 5
LOCKOUT_WINDOW_MIN = 15
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"

router = APIRouter(prefix="/auth", tags=["auth"])


# ────────────────────────── helpers ──────────────────────────
def _secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError("JWT_SECRET not set — refusing to start auth without a real secret")
    return s


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["_id"], "email": user["email"], "role": user["role"], "name": user.get("name", ""),
        "type": "access", "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG)


def create_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": user_id, "type": "refresh", "iat": int(now.timestamp()),
               "exp": int((now + timedelta(days=REFRESH_TTL_DAYS)).timestamp()),
               "jti": secrets.token_hex(8)}
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG)


def _set_cookies(resp: Response, access: str, refresh: str) -> None:
    common = {"httponly": True, "secure": COOKIE_SECURE, "samesite": "lax", "path": "/"}
    resp.set_cookie("access_token", access, max_age=ACCESS_TTL_MIN * 60, **common)
    resp.set_cookie("refresh_token", refresh, max_age=REFRESH_TTL_DAYS * 86400, **common)


def _clear_cookies(resp: Response) -> None:
    resp.delete_cookie("access_token", path="/")
    resp.delete_cookie("refresh_token", path="/")


def _extract_token(request: Request) -> Optional[str]:
    # 1. Authorization: Bearer <token>
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    # 2. httpOnly cookie
    c = request.cookies.get("access_token")
    if c:
        return c
    # 3. SSE fallback — EventSource can't set headers
    q = request.query_params.get("token")
    return q or None


def _decode(token: str, kind: str = "access") -> dict:
    try:
        payload = jwt.decode(token, _secret(), algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    if payload.get("type") != kind:
        raise HTTPException(status_code=401, detail="wrong token type")
    return payload


async def get_current_user(request: Request) -> dict:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    payload = _decode(token, "access")
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    user.pop("password_hash", None)
    return user


def require_role(*roles: str):
    """Dependency factory: allow only users whose role is one of `roles` OR admin."""
    allowed = set(roles) | {"admin"}
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in allowed:
            raise HTTPException(status_code=403, detail=f"forbidden — requires role in {sorted(allowed)}")
        return user
    return _dep


def role_at_least(user: dict, min_role: str) -> bool:
    return ROLE_RANK.get(user.get("role"), -1) >= ROLE_RANK.get(min_role, 99)


# ────────────────────────── brute force ──────────────────────────
async def _is_locked(identifier: str) -> Optional[datetime]:
    doc = await db.login_attempts.find_one({"_id": identifier})
    if not doc:
        return None
    until = doc.get("locked_until")
    if not until:
        return None
    try:
        u = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except Exception:
        return None
    return u if u > datetime.now(timezone.utc) else None


async def _record_failure(identifier: str) -> None:
    doc = await db.login_attempts.find_one({"_id": identifier}) or {"count": 0}
    count = int(doc.get("count", 0)) + 1
    upd = {"count": count, "last_at": now_iso()}
    if count >= LOCKOUT_FAIL_LIMIT:
        until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_WINDOW_MIN)
        upd["locked_until"] = until.isoformat()
    await db.login_attempts.update_one({"_id": identifier}, {"$set": upd}, upsert=True)


async def _clear_failures(identifier: str) -> None:
    await db.login_attempts.delete_one({"_id": identifier})


# ────────────────────────── schemas ──────────────────────────
class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class RegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: str = ""
    role: str = "operator"


class ChangePwBody(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


def _public_user(u: dict) -> dict:
    return {"id": u["_id"], "email": u["email"], "name": u.get("name", ""),
            "role": u.get("role", "viewer"), "created_at": u.get("created_at"),
            "last_login": u.get("last_login")}


# ────────────────────────── routes ──────────────────────────
@router.post("/login")
async def login(request: Request, response: Response, body: LoginBody):
    email = body.email.lower().strip()
    ip = (request.client.host if request.client else "?")
    identifier = f"{ip}:{email}"

    lock = await _is_locked(identifier)
    if lock:
        raise HTTPException(status_code=429, detail=f"too many failed attempts — locked until {lock.isoformat()}")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        await _record_failure(identifier)
        raise HTTPException(status_code=401, detail="invalid credentials")

    await _clear_failures(identifier)
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now_iso()}})

    access = create_access_token(user)
    refresh = create_refresh_token(user["_id"])
    _set_cookies(response, access, refresh)
    return {"user": _public_user(user), "access_token": access, "refresh_token": refresh,
            "token_type": "Bearer", "expires_in": ACCESS_TTL_MIN * 60}


@router.post("/logout")
async def logout(response: Response, _u: dict = Depends(get_current_user)):
    _clear_cookies(response)
    return {"ok": True}


@router.post("/refresh")
async def refresh(request: Request, response: Response, body: Optional[dict] = Body(default=None)):
    token = (body or {}).get("refresh_token") or request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="no refresh token")
    payload = _decode(token, "refresh")
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    access = create_access_token(user)
    new_refresh = create_refresh_token(user["_id"])
    _set_cookies(response, access, new_refresh)
    return {"user": _public_user(user), "access_token": access, "refresh_token": new_refresh,
            "token_type": "Bearer", "expires_in": ACCESS_TTL_MIN * 60}


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": _public_user(user)}


@router.post("/change-password")
async def change_password(body: ChangePwBody, user: dict = Depends(get_current_user)):
    full = await db.users.find_one({"_id": user["_id"]})
    if not full or not verify_password(body.current_password, full.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="current password incorrect")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": hash_password(body.new_password)}})
    return {"ok": True}


@router.get("/users")
async def list_users(_admin: dict = Depends(require_role("admin"))):
    users = await db.users.find({}).sort("created_at", 1).to_list(500)
    return {"users": [_public_user(u) for u in users]}


@router.post("/users")
async def create_user(body: RegisterBody, _admin: dict = Depends(require_role("admin"))):
    email = body.email.lower().strip()
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {list(ROLES)}")
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="user already exists")
    u = {"_id": uuid.uuid4().hex, "email": email, "password_hash": hash_password(body.password),
         "name": body.name or email.split("@")[0], "role": body.role, "created_at": now_iso(),
         "last_login": None}
    await db.users.insert_one(u)
    return {"user": _public_user(u)}


@router.delete("/users/{uid}")
async def delete_user(uid: str, admin: dict = Depends(require_role("admin"))):
    if uid == admin["_id"]:
        raise HTTPException(status_code=400, detail="cannot delete yourself")
    r = await db.users.delete_one({"_id": uid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="user not found")
    return {"ok": True}


# ────────────────────────── startup: seed admin + indexes ──────────────────────────
async def ensure_indexes():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("last_at")


async def seed_admin():
    email = (os.environ.get("SEED_ADMIN_EMAIL") or "").lower().strip()
    pw = os.environ.get("SEED_ADMIN_PASSWORD") or ""
    if not email or not pw:
        return None
    existing = await db.users.find_one({"email": email})
    if existing:
        # rotate password if env changed (idempotent)
        if not verify_password(pw, existing.get("password_hash", "")):
            await db.users.update_one({"_id": existing["_id"]},
                                      {"$set": {"password_hash": hash_password(pw), "role": "admin"}})
        return existing["_id"]
    uid = uuid.uuid4().hex
    try:
        await db.users.insert_one({
            "_id": uid, "email": email, "password_hash": hash_password(pw),
            "name": os.environ.get("SEED_ADMIN_NAME", "Admin"), "role": "admin",
            "created_at": now_iso(), "last_login": None,
        })
    except DuplicateKeyError:
        # Another worker seeded the admin first — race-safe: reuse the existing row.
        existing = await db.users.find_one({"email": email})
        return existing["_id"] if existing else None
    return uid
