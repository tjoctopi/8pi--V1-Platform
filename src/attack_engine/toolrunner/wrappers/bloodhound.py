"""BloodHound AD collector wrapper — identity attack-surface collection (O5).

Runs the Python BloodHound collector (``bloodhound-python``) against a domain
with supplied credentials to gather users, groups, computers, sessions, and ACLs
— the data the :class:`~attack_engine.ad.graph.ADGraph` turns into attack paths.
Collection is read-only (LDAP/SMB queries), scope-enforced, and audited; the
credentials come from the engagement, never guessed here.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


class BloodHoundWrapper(ToolWrapper):
    name = "bloodhound"
    default_image = "ghcr.io/dirkjanm/bloodhound.py:latest"
    default_timeout_sec = 900

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        domain = str(profile.args.get("domain", ""))
        username = str(profile.args.get("username", ""))
        if not domain or not username:
            raise ValueError("bloodhound requires 'domain' and 'username' args")
        argv = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-c", str(profile.args.get("collection", "DCOnly")),  # low-touch default
            "-ns", target,          # the DC / nameserver to query
            "--zip",
        ]
        password = profile.args.get("password")
        nthash = profile.args.get("hash")
        if isinstance(password, str) and password:
            argv += ["-p", password]
        elif isinstance(nthash, str) and nthash:
            argv += ["--hashes", nthash]
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False  # LDAP/SMB collection only

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        text = result.stdout.decode("utf-8", errors="replace")
        counts: dict[str, int] = {}
        # bloodhound-python logs "INFO: Found N users/groups/computers".
        import re
        for kind in ("users", "groups", "computers", "domains"):
            m = re.search(rf"Found (\d+) {kind}", text)
            if m:
                counts[kind] = int(m.group(1))
        # If a collector emitted a JSON summary on stdout, prefer it.
        try:
            doc = json.loads(text)
            if isinstance(doc, dict):
                counts.update({k: int(v) for k, v in doc.items() if isinstance(v, int)})
        except (json.JSONDecodeError, ValueError):
            pass
        return {"tool": self.name, "target": target, "collected": counts}
