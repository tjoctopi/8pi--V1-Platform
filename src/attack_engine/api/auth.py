"""Authentication for the API shell — JWT + stdlib password hashing.

Deliberately dependency-light: PyJWT for HS256 tokens (already present) and
``hashlib.pbkdf2_hmac`` for password hashing (stdlib), so the server needs no
bcrypt/passlib. Roles mirror the engine's RBAC vocabulary exactly
(viewer < operator < approver < admin) so a logged-in user maps cleanly onto an
engine :class:`~attack_engine.governance.rbac.Principal`.

Token transport matches what the console expects (``frontend/src/lib/api.js``):
``Authorization: Bearer`` header, or a ``?token=`` query param for SSE/file URLs
where a header can't be set.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
from fastapi import Depends, HTTPException, Query, Request, status

from .store import ShellStore

_ALG = "HS256"
_ACCESS_TTL = timedelta(hours=12)
_REFRESH_TTL = timedelta(days=7)
_ROLE_RANK = {"viewer": 0, "operator": 1, "approver": 2, "admin": 3}

_PBKDF2_ROUNDS = 240_000


def _secret() -> str:
    # A stable secret across a process; env overrides for real deployments.
    key = os.environ.get("AE_API_JWT_SECRET")
    if not key:
        key = os.environ.setdefault("AE_API_JWT_SECRET", secrets.token_urlsafe(48))
    return key


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ── password hashing (pbkdf2, stdlib) ────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, rounds, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ── tokens ────────────────────────────────────────────────────────────────

def _encode(claims: dict[str, Any], ttl: timedelta) -> str:
    payload = {
        **claims,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + ttl,
    }
    return jwt.encode(payload, _secret(), algorithm=_ALG)


def make_tokens(user: dict[str, Any]) -> dict[str, Any]:
    base = {"sub": user["id"], "email": user["email"], "role": user["role"],
            "name": user["name"]}
    return {
        "access_token": _encode({**base, "type": "access"}, _ACCESS_TTL),
        "refresh_token": _encode({"sub": user["id"], "type": "refresh"}, _REFRESH_TTL),
        "token_type": "Bearer",
        "expires_in": int(_ACCESS_TTL.total_seconds()),
    }


def decode(token: str) -> dict[str, Any]:
    return jwt.decode(token, _secret(), algorithms=[_ALG])


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {k: user.get(k) for k in ("id", "email", "name", "role", "created_at", "last_login")}


def role_at_least(user: dict[str, Any], minimum: str) -> bool:
    return _ROLE_RANK.get(user.get("role", "viewer"), 0) >= _ROLE_RANK.get(minimum, 99)


# ── FastAPI dependencies ────────────────────────────────────────────────────

def _extract_token(request: Request, token_q: str | None) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    if token_q:  # SSE / file URLs
        return token_q
    cookie = request.cookies.get("access_token")
    return cookie or None


def get_store(request: Request) -> ShellStore:
    return cast(ShellStore, request.app.state.store)


async def get_current_user(
    request: Request,
    token: str | None = Query(default=None),
    store: ShellStore = Depends(get_store),
) -> dict[str, Any]:
    raw = _extract_token(request, token)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    try:
        claims = decode(raw)
    except jwt.PyJWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid or expired token"
        ) from None
    if claims.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
    user = store.user_by_id(claims.get("sub", ""))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user no longer exists")
    return user


def require_role(
    minimum: str,
) -> Callable[..., Coroutine[Any, Any, dict[str, Any]]]:
    """Dependency factory: 403 unless the user's role rank ≥ ``minimum``."""

    async def _dep(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if not role_at_least(user, minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"requires role {minimum} or higher"
            )
        return user

    return _dep


def seed_admin(store: ShellStore) -> str | None:
    """Ensure an admin exists (env-driven), so first login works. Returns id."""

    if store.user_count() > 0:
        return None
    email = os.environ.get("AE_API_ADMIN_EMAIL", "admin@8pi.local")
    password = os.environ.get("AE_API_ADMIN_PASSWORD", "changeme-8pi")
    uid = f"u-{secrets.token_hex(8)}"
    store.create_user({
        "id": uid, "email": email, "name": "8pi Admin", "role": "admin",
        "pw_hash": hash_password(password), "created_at": now_iso(), "last_login": None,
    })
    return uid
