"""Passive/active discovery wrappers (read-only) — subfinder, amass, searchsploit.

These broaden the recon and weaponise phases: subdomain/asset discovery and a
local exploit-DB lookup. All read-only — no packets that change target state,
no impact. searchsploit queries an offline database and touches no target.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class SubfinderWrapper(ToolWrapper):
    name = "subfinder"
    default_image = "projectdiscovery/subfinder:latest"
    default_timeout_sec = 300

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        return ["subfinder", "-d", target, "-silent", "-json"]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        hosts: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("host"):
                hosts.append(doc["host"])
        return {"tool": self.name, "domain": target, "subdomains": hosts}


class AmassWrapper(ToolWrapper):
    name = "amass"
    default_image = "caffix/amass:latest"
    default_timeout_sec = 900

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        mode = "passive" if profile.args.get("passive", True) else "active"
        argv = ["amass", "enum", "-d", target, "-silent"]
        if mode == "passive":
            argv.append("-passive")
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        hosts = [
            line.strip().split()[0]
            for line in result.stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        return {"tool": self.name, "domain": target, "subdomains": hosts}


class SearchsploitWrapper(ToolWrapper):
    name = "searchsploit"
    default_image = "toolhub/searchsploit:latest"
    default_timeout_sec = 60

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        # ``target`` here is a product/version search term, not a network target.
        return ["searchsploit", "--json", target]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False  # offline exploit-DB lookup; touches no target

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "term": target, "exploits": []}
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        for e in doc.get("RESULTS_EXPLOIT", []):
            parsed["exploits"].append(
                {"title": e.get("Title"), "path": e.get("Path"), "edb_id": e.get("EDB-ID")}
            )
        return parsed
