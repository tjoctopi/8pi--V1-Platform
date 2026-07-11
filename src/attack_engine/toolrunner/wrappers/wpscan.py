"""WPScan wrapper — WordPress enumeration (read-only).

Enumerates WordPress version, plugins, and known vulnerabilities. Read-only:
we never run brute-force (``--enumerate`` only, never ``--passwords``).
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class WpscanWrapper(ToolWrapper):
    name = "wpscan"
    default_image = "wpscanteam/wpscan:latest"
    default_timeout_sec = 1200

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        scheme = str(profile.args.get("scheme", "http"))
        url = target if "://" in target else f"{scheme}://{target}"
        enumerate = str(profile.args.get("enumerate", "vp,vt,cb,dbe"))  # vuln plugins/themes
        return [
            "wpscan", "--url", url, "--format", "json", "--no-banner",
            "--enumerate", enumerate,
        ]

    def is_mutating(self, profile: ToolProfile) -> bool:
        # Enumeration is read-only; password attacks (never used here) would not be.
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "tool": self.name,
            "target": target,
            "version": None,
            "vulnerabilities": [],
        }
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed

        version = (doc.get("version") or {}).get("number")
        parsed["version"] = version
        # Collect vulns from the core version and each enumerated plugin.
        for v in (doc.get("version") or {}).get("vulnerabilities", []) or []:
            parsed["vulnerabilities"].append(
                {"title": v.get("title"), "component": "core", "references": v.get("references")}
            )
        for plugin_name, plugin in (doc.get("plugins") or {}).items():
            for v in plugin.get("vulnerabilities", []) or []:
                parsed["vulnerabilities"].append(
                    {"title": v.get("title"), "component": f"plugin:{plugin_name}",
                     "references": v.get("references")}
                )
        return parsed
