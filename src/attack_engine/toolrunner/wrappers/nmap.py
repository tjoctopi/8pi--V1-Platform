"""Nmap wrapper — network recon (read-only).

We drive Nmap with XML output to stdout (``-oX -``) and parse it deterministically
with the stdlib XML parser — never scraping human-readable text, which changes
between versions. Presets map to safe, read-only scan profiles; nothing here
mutates a target.
"""

from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

# Preset -> the scan-shaping flags. ``-sT`` (TCP connect scan) is used instead of
# the default SYN scan so nmap needs no raw socket — it runs inside the hardened
# sandbox (``--cap-drop ALL``), which forbids raw sockets. Everything here is
# read-only / non-intrusive.
_PRESETS: dict[str, list[str]] = {
    # Fast: top-100 ports, no version detection.
    "quick": ["-T4", "-sT", "-F", "-Pn"],
    # Default: service/version detection on the default top-1000 ports.
    "default": ["-T4", "-sT", "-sV", "-Pn"],
    # Thorough: all 65535 ports with version detection.
    "full": ["-T4", "-sT", "-sV", "-p-", "-Pn"],
}


class NmapWrapper(ToolWrapper):
    name = "nmap"
    default_image = "instrumentisto/nmap:latest"
    default_timeout_sec = 900

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        flags = list(_PRESETS.get(profile.preset, _PRESETS["default"]))
        # Optional explicit port spec overrides the preset's port selection.
        ports = profile.args.get("ports")
        if isinstance(ports, str) and ports:
            # Strip any preset -p/-F flags to avoid conflicts.
            flags = [f for f in flags if f not in ("-F", "-p-")]
            flags += ["-p", ports]
        argv = ["nmap", *flags, "-oX", "-", target]
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False  # Nmap recon is always read-only in our presets.

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        ports: list[dict[str, Any]] = []
        parsed: dict[str, Any] = {
            "tool": self.name,
            "host": target,
            "ports": ports,
            "up": False,
        }
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            parsed["parse_error"] = True
            return parsed

        host_el = root.find("host")
        if host_el is None:
            return parsed
        status = host_el.find("status")
        parsed["up"] = status is not None and status.get("state") == "up"

        for port_el in host_el.iterfind("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            entry: dict[str, Any] = {
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": "open",
                "service": svc_el.get("name") if svc_el is not None else None,
                "product": svc_el.get("product") if svc_el is not None else None,
                "version": svc_el.get("version") if svc_el is not None else None,
            }
            ports.append(entry)
        return parsed
