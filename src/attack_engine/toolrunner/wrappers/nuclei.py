"""Nuclei wrapper — the breadth unlock (spec §7).

Nuclei is a single templated scanner backed by thousands of community
templates; wrapping it once turns "every way of attacking" into registry
entries — add coverage by adding templates, not agents (rule #3). We run it in
JSONL mode and parse one finding per line. Template scanning is read-only.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

_SEVERITY_PRESETS: dict[str, list[str]] = {
    "default": ["-severity", "low,medium,high,critical"],
    "info": ["-severity", "info,low,medium,high,critical"],
    "high-only": ["-severity", "high,critical"],
}

#: Container path the pre-seeded nuclei-templates tree is mounted at.
_TEMPLATE_DIR = "/nuclei-templates"


class NucleiWrapper(ToolWrapper):
    name = "nuclei"
    default_image = "projectdiscovery/nuclei:latest"
    default_timeout_sec = 1200

    @staticmethod
    def _templates_source() -> str:
        from ...config import get_settings

        return get_settings().nuclei_templates_source

    @staticmethod
    def _build_url(target: str, profile: ToolProfile) -> str:
        # The Tool Runner validates a bare host/IP against scope, so agents pass
        # one plus scheme/port in the profile; a full URL target is used as-is.
        if "://" in target:
            return target
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        hostport = f"{target}:{port}" if port else target
        return f"{scheme}://{hostport}"

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        flags = list(_SEVERITY_PRESETS.get(profile.preset, _SEVERITY_PRESETS["default"]))
        tags = profile.args.get("tags")
        if isinstance(tags, str) and tags:
            flags += ["-tags", tags]
        url = self._build_url(target, profile)
        argv = ["nuclei", "-u", url, "-jsonl", "-silent", "-no-color", *flags]
        # Air-gapped, reproducible scans: never phone home to fetch/update
        # templates. When a template source is configured, run from the mounted,
        # read-only tree; otherwise fall back to the image's default dir.
        argv += ["-duc"]  # -disable-update-check
        if self._templates_source():
            argv += ["-t", _TEMPLATE_DIR]
        return argv

    def mounts(self, profile: ToolProfile) -> list[tuple[str, str]]:
        source = self._templates_source()
        return [(source, _TEMPLATE_DIR)] if source else []

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = doc.get("info", {})
            results.append(
                {
                    "template_id": doc.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": doc.get("matched-at") or doc.get("host"),
                    "type": doc.get("type"),
                }
            )
        return {"tool": self.name, "target": target, "results": results}
