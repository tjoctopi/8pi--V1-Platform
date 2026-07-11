"""katana wrapper — web crawler / endpoint discovery (read-only).

Crawls a web app to enumerate endpoints and, crucially, *parameterised* URLs —
the injection points that feed the Exploit-Confirmer. Read-only spidering.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class KatanaWrapper(ToolWrapper):
    name = "katana"
    default_image = "projectdiscovery/katana:latest"
    default_timeout_sec = 600

    @staticmethod
    def _url(target: str, profile: ToolProfile) -> str:
        if "://" in target:
            return target
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        return f"{scheme}://{target}:{port}" if port else f"{scheme}://{target}"

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        depth = str(profile.args.get("depth", "2"))
        argv = [
            "katana", "-u", self._url(target, profile),
            "-jsonl", "-silent", "-d", depth, "-duc",
            # -jc: crawl JavaScript to recover SPA/API endpoints (the routes a
            #      single-page app calls via XHR — invisible to plain crawling).
            # -kf all: also parse known files (robots.txt, sitemap.xml).
            "-jc", "-kf", "all",
        ]
        if profile.args.get("headless"):
            argv.append("-headless")  # render JS-heavy apps when a browser is available
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        endpoints: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = doc.get("endpoint") or (doc.get("request") or {}).get("endpoint")
            if not url or url in seen:
                continue
            seen.add(url)
            parts = urlsplit(url)
            params = [p.split("=", 1)[0] for p in parts.query.split("&") if p]
            endpoints.append({"url": url, "path": parts.path, "params": params})
        return {"tool": self.name, "target": target, "endpoints": endpoints}
