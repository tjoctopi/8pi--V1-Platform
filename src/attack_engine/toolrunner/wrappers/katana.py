"""katana wrapper — web crawler / endpoint discovery (read-only).

Crawls a web app to enumerate endpoints and, crucially, *parameterised* URLs —
the injection points that feed the Exploit-Confirmer. Read-only spidering.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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
            # -fx: extract HTML <form>s (the POST endpoints a plain crawl misses —
            #      e.g. a dns-lookup form whose `target_host` field reaches a shell).
            # -aff: automatically fill and enqueue forms, so the crawler emits the
            #       POST request (method + body) that names each form field. Without
            #       these, command-injection points behind POST forms are invisible
            #       and Full Attack never reaches a foothold.
            "-fx", "-aff",
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
            request = doc.get("request") or {}
            url = doc.get("endpoint") or request.get("endpoint")
            if not url:
                continue
            method = str(request.get("method") or "GET").upper()
            # A form POST and its GET twin are distinct injection surfaces, so the
            # dedup key includes the method (otherwise the crawler's GET of the same
            # page would mask the form's POST body fields).
            key = f"{method} {url}"
            if key in seen:
                continue
            seen.add(key)
            parts = urlsplit(url)
            params = [p.split("=", 1)[0] for p in parts.query.split("&") if p]
            ep: dict[str, Any] = {
                "url": url, "path": parts.path, "params": params, "method": method,
            }
            # POST form: -fx/-aff fill the body with each field name, so parse the
            # urlencoded body into {field: filled_value}. These become the injectable
            # candidate params (and their companions ride as fixed `data`).
            if method in ("POST", "PUT"):
                body = request.get("body")
                if isinstance(body, str) and body:
                    ep["form"] = dict(parse_qsl(body, keep_blank_values=True))
            endpoints.append(ep)
        return {"tool": self.name, "target": target, "endpoints": endpoints}
