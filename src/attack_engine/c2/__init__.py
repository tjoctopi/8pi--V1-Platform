"""Command & control / post-exploitation (O3).

Once exploitation (O2) opens a foothold, realistic offense happens *after* access.
This package provides the session-management and post-exploitation layer:

* :class:`~attack_engine.c2.session.SessionManager` — a scope-bound, audited
  registry of live authorized sessions, plus the reverse-shell **listeners** that
  give exploitation a known callback endpoint (closing O2's LHOST gap).
* :class:`~attack_engine.c2.backend.C2Backend` — how post-ex commands actually
  reach a session (Metasploit RPC / Sliver / a test mock); the rest of the engine
  is backend-agnostic.
* :class:`~attack_engine.c2.postex.PostExOperator` — typed, scope-checked,
  authorized, audited post-access operations (enumerate / collect / pivot).

Every action is governed exactly like the rest of the platform: in-scope only,
authorized at the engagement boundary (or gated), kill-switchable, fully audited.
"""

from __future__ import annotations

from .backend import C2Backend, MockC2Backend
from .foothold import Foothold, FootholdRunner
from .msf import MsfFootholdLauncher, MsfRpcBackend, MsfRpcClient
from .postex import PostExOperator, PostExReport, PostExResult
from .session import Listener, Session, SessionKind, SessionManager, SessionStatus
from .sliver import SliverC2Backend, SliverClient
from .webshell import WebInjectionPoint, WebShellBackend, web_shell_backend

__all__ = [
    "C2Backend",
    "MockC2Backend",
    "Foothold",
    "FootholdRunner",
    "MsfRpcBackend",
    "MsfRpcClient",
    "MsfFootholdLauncher",
    "SliverC2Backend",
    "SliverClient",
    "WebShellBackend",
    "WebInjectionPoint",
    "web_shell_backend",
    "Listener",
    "Session",
    "SessionKind",
    "SessionManager",
    "SessionStatus",
    "PostExOperator",
    "PostExReport",
    "PostExResult",
]
