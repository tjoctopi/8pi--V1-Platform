"""Licensed/commercial scanner wrappers — gated behind procurement (spec §7).

Nessus and Burp Suite Enterprise are only permitted *after* procurement, legal,
and headless-terms sign-off. That sign-off is represented in the engagement RoE
(``licensed_tools_enabled``); the Tool Runner refuses these wrappers otherwise,
so a licensed tool can never run by default. Both real products are API-driven
(REST), so these wrappers model the registry contract and output parsing —
the live API client is a later, credential-bearing integration.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class NessusWrapper(ToolWrapper):
    """Tenable Nessus (commercial vulnerability scanner)."""

    name = "nessus"
    default_image = "tenable/nessus:latest"
    default_timeout_sec = 3600
    licensed = True

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        policy = str(profile.args.get("policy", "basic-network-scan"))
        # Real deployments call the Nessus REST API; this argv drives a
        # thin client shim inside the licensed image.
        return ["nessus-scan", "--target", target, "--policy", policy, "--format", "json"]

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
        for v in doc.get("vulnerabilities", []):
            parsed["findings"].append(
                {
                    "plugin_id": v.get("plugin_id"),
                    "name": v.get("plugin_name") or v.get("name"),
                    "severity": v.get("severity"),
                    "cve": v.get("cve"),
                }
            )
        return parsed


class BurpEnterpriseWrapper(ToolWrapper):
    """PortSwigger Burp Suite Enterprise (commercial web scanner)."""

    name = "burp_enterprise"
    default_image = "portswigger/burp-enterprise-scanner:latest"
    default_timeout_sec = 3600
    licensed = True

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        scheme = str(profile.args.get("scheme", "https"))
        url = target if "://" in target else f"{scheme}://{target}"
        config = str(profile.args.get("config", "audit-coverage-maximum"))
        return ["burp-scan", "--url", url, "--config", config, "--report", "json"]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "target": target, "issues": []}
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        for issue in doc.get("issue_events", []) or doc.get("issues", []):
            data = issue.get("issue", issue)
            parsed["issues"].append(
                {
                    "type": data.get("type_index") or data.get("name"),
                    "name": data.get("name"),
                    "severity": data.get("severity"),
                    "path": data.get("path"),
                }
            )
        return parsed
