"""masscan wrapper — internet-scale port discovery (read-only recon).

Complements Nmap: masscan sweeps huge port/address ranges fast to find what's
open, then Nmap does slow, accurate version detection on just those ports. A
SYN sweep is non-intrusive discovery, so this is read-only. Rate is bounded by
the profile (and again by the Tool Runner's RoE rate limiter).
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class MasscanWrapper(ToolWrapper):
    name = "masscan"
    default_image = "ivre/masscan:latest"
    default_timeout_sec = 600

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        ports = str(profile.args.get("ports", "1-1024"))
        rate = str(profile.args.get("rate", "1000"))
        return ["masscan", target, "-p", ports, "--rate", rate, "-oJ", "-"]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "host": target, "ports": []}
        raw = result.stdout.strip().rstrip(b",")  # masscan JSON can trail a comma
        if not raw:
            return parsed
        # masscan -oJ emits a JSON array (sometimes newline-delimited objects).
        try:
            doc = json.loads(raw if raw.startswith(b"[") else b"[" + raw + b"]")
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        for entry in doc:
            for p in entry.get("ports", []):
                if p.get("status") == "open":
                    parsed["ports"].append(
                        {"port": int(p["port"]), "protocol": p.get("proto", "tcp"),
                         "state": "open"}
                    )
        return parsed
