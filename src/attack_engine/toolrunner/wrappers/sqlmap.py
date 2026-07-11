"""SQLMap wrapper — CONFIRM ONLY (spec §4, §9 Sprint 1).

This wrapper is deliberately crippled to *confirmation*: boolean-based blind
technique only (``--technique=B``), lowest level/risk, and — critically — no
data-extraction flags are ever emitted (no ``--dump``, ``--dbs``, ``--tables``,
``--os-shell``…). It detects whether an injection point exists; it never pulls a
row. Even so, the Exploit-Confirmer archetype must pass a **hard human gate**
before invoking it (enforced in the agent spec + runtime), and an independent
oracle re-confirms the result.
"""

from __future__ import annotations

import re
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

#: Flags that would turn confirmation into exploitation. Refused outright.
_FORBIDDEN_ARGS = {
    "--dump", "--dump-all", "--dbs", "--tables", "--columns", "--os-shell",
    "--os-pwn", "--sql-shell", "--file-read", "--file-write", "--passwords",
}


class SqlmapConfirmWrapper(ToolWrapper):
    name = "sqlmap_confirm"
    default_image = "googlesky/sqlmap:latest"
    default_timeout_sec = 900

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        path = str(profile.args.get("path", "/"))
        param = profile.args.get("param")
        params = profile.args.get("params") or {}
        hostport = f"{target}:{port}" if port else target
        from urllib.parse import urlencode

        query = f"?{urlencode(params)}" if params else ""
        url = target if "://" in target else f"{scheme}://{hostport}{path}{query}"

        argv = [
            "sqlmap", "-u", url,
            "--batch",              # non-interactive
            "--technique=B",        # boolean-based blind ONLY
            "--level=1", "--risk=1",
            "--flush-session",
            "--answers=quit=N",
        ]
        if isinstance(param, str) and param:
            argv += ["-p", param]
        # Defence in depth: never allow an extraction flag to slip through.
        extra = profile.args.get("extra_args") or []
        for a in extra:
            if any(a.startswith(f) for f in _FORBIDDEN_ARGS):
                raise ValueError(f"SQLMap extraction flag {a!r} is forbidden (confirm-only)")
        return argv + list(extra)

    def is_mutating(self, profile: ToolProfile) -> bool:
        # Boolean-blind confirmation reads only; it does not alter target state.
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        text = result.stdout.decode("utf-8", errors="replace")
        injectable = bool(re.search(r"is vulnerable|Parameter:.*\n.*boolean-based blind", text))
        param_match = re.search(r"Parameter:\s*([^\s(]+)", text)
        return {
            "tool": self.name,
            "target": target,
            "injectable": injectable,
            "parameter": param_match.group(1) if param_match else None,
            "technique": "boolean-based blind" if injectable else None,
        }
