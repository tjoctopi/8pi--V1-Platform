"""httpx wrapper — fast HTTP probing & tech fingerprinting (read-only).

Given a host/port, resolves the live HTTP(S) surface: status, title, web server,
and detected technologies. It enriches the recon inventory (accurate product /
version for the correlator) far faster than a full Nmap ``-sV`` pass.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class HttpxWrapper(ToolWrapper):
    name = "httpx"
    default_image = "projectdiscovery/httpx:latest"
    default_timeout_sec = 30

    @staticmethod
    def _url(target: str, profile: ToolProfile) -> str:
        if "://" in target:
            return target
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        return f"{scheme}://{target}:{port}" if port else f"{scheme}://{target}"

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        # -duc: never phone home for updates (air-gapped, deterministic runs).
        # We deliberately omit -tech-detect: recent httpx builds back it with a
        # ~90MB ML model fetched from the internet on first use, which stalls in
        # a sandboxed/offline network. Technology fingerprinting is handled in
        # the pipeline by Nuclei (fingerprinthub / app-detect templates); httpx
        # stays fast and offline, returning status/title/server for web-surface
        # classification and inventory enrichment.
        return [
            "httpx", "-u", self._url(target, profile),
            "-json", "-silent", "-no-color", "-duc",
            "-status-code", "-title", "-web-server",
        ]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "target": target, "results": []}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed["results"].append(
                {
                    "url": doc.get("url"),
                    "status": doc.get("status_code") or doc.get("status-code"),
                    "title": doc.get("title"),
                    "webserver": doc.get("webserver") or doc.get("web-server"),
                    "tech": doc.get("tech") or doc.get("technologies") or [],
                }
            )
        return parsed
