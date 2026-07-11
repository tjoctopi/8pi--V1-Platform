"""Nikto wrapper — web server misconfiguration/known-issue scanner (read-only)."""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class NiktoWrapper(ToolWrapper):
    name = "nikto"
    default_image = "frapsoft/nikto:latest"
    default_timeout_sec = 1200

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port", 80)
        host = f"{scheme}://{target}"
        # The frapsoft/nikto image ships the scanner as ``nikto.pl`` (its
        # original ENTRYPOINT); we clear the image entrypoint uniformly in the
        # sandbox, so we invoke that executable by name explicitly.
        return ["nikto.pl", "-h", host, "-p", str(port), "-Format", "json", "-output", "-"]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "target": target, "results": []}
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        # Nikto JSON may be a dict with "vulnerabilities" or a list of hosts.
        vulns = []
        if isinstance(doc, dict):
            vulns = doc.get("vulnerabilities", [])
        elif isinstance(doc, list) and doc and isinstance(doc[0], dict):
            vulns = doc[0].get("vulnerabilities", [])
        for v in vulns:
            parsed["results"].append(
                {
                    "id": v.get("id"),
                    "message": v.get("msg"),
                    "url": v.get("url"),
                    "method": v.get("method", "GET"),
                }
            )
        return parsed
