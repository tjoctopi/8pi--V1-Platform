"""dalfox wrapper — XSS discovery/confirmation (read-only reflection tests).

Adds cross-site-scripting coverage to the web phase. dalfox reflects benign
probe payloads to detect exploitable injection points; it does not alter target
state, so it is read-only (like Nuclei/Nikto probes). Confirmed points are
proposed as ``xss-reflected`` findings for triage.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class DalfoxWrapper(ToolWrapper):
    name = "dalfox"
    default_image = "hahwul/dalfox:latest"
    default_timeout_sec = 600

    @staticmethod
    def _url(target: str, profile: ToolProfile) -> str:
        if "://" in target:
            return target
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        path = str(profile.args.get("path", "/"))
        base = f"{scheme}://{target}:{port}" if port else f"{scheme}://{target}"
        return base + (path if path.startswith("/") else "/" + path)

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        # The hahwul/dalfox image installs the binary at /app/dalfox (not on
        # PATH); with the image entrypoint cleared we invoke it by full path.
        # dalfox v3 takes the target via the ``--url`` flag (v2 used a positional
        # arg); ``--silence`` suppresses the banner, JSON goes to stdout.
        return [
            "/app/dalfox", "url", "--url", self._url(target, profile),
            "--format", "json", "--silence",
        ]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "target": target, "findings": []}
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        # dalfox v3 emits {"findings": [...], "meta": {...}}; older builds emit a
        # bare list (or {"pocs": [...]}). Accept all three.
        items = doc if isinstance(doc, list) else doc.get("findings") or doc.get("pocs") or []
        for poc in items:
            if not isinstance(poc, dict):
                continue
            parsed["findings"].append(
                {
                    "param": poc.get("param"),
                    "inject_type": poc.get("inject_type") or poc.get("type"),
                    "evidence": poc.get("evidence") or poc.get("poc"),
                    "method": poc.get("method", "GET"),
                }
            )
        return parsed
