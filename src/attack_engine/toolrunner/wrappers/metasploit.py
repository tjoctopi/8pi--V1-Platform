"""Metasploit wrapper — CHECK-ONLY exploit confirmation (spec §4, rule #1).

Metasploit is the most capable confirmation engine we can wire, but it is also
the most dangerous, so this wrapper is doubly constrained:

* It only ever runs a module's ``check`` action (does the target *appear*
  vulnerable?) — never ``exploit``/``run``/payload delivery. Any such token in
  the requested actions is refused outright.
* ``check`` can be intrusive, so the wrapper is ``mutating`` — the Tool Runner
  refuses it under a read-only engagement. Running it therefore requires an RoE
  that is explicitly not read-only *and* the exploit-confirm human gate.

This gives real exploitation-grade confirmation while keeping the propose/verify
and human-gate discipline intact.
"""

from __future__ import annotations

import re
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

_FORBIDDEN_ACTIONS = {"exploit", "run", "rexploit", "rerun", "to_handler"}
#: msfconsole is not on PATH in the official image; invoke it by full path
#: (the sandbox clears the image entrypoint).
_MSFCONSOLE = "/usr/src/metasploit-framework/msfconsole"


class MetasploitCheckWrapper(ToolWrapper):
    name = "metasploit_check"
    default_image = "metasploitframework/metasploit-framework:latest"
    default_timeout_sec = 900

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        module = str(profile.args.get("module", ""))
        if not module:
            raise ValueError("metasploit_check requires a 'module' arg")
        port = profile.args.get("port")
        # Reject any attempt to smuggle an exploitation action through.
        for action in profile.args.get("actions", []):
            if str(action).lower() in _FORBIDDEN_ACTIONS:
                raise ValueError(f"metasploit action {action!r} forbidden (check-only)")
        setup = [f"use {module}", f"set RHOSTS {target}"]
        if port:
            setup.append(f"set RPORT {port}")
        setup += ["check", "exit"]
        resource = "; ".join(setup)
        return [_MSFCONSOLE, "-q", "-x", resource]

    def is_mutating(self, profile: ToolProfile) -> bool:
        # `check` probes the target; treat as mutating so read-only RoE blocks it.
        return True

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        text = result.stdout.decode("utf-8", errors="replace")
        vulnerable = bool(
            re.search(r"is vulnerable|appears? to be vulnerable|The target is vulnerable", text)
        )
        safe = bool(re.search(r"is not vulnerable|does not appear to be vulnerable", text))
        return {
            "tool": self.name,
            "target": target,
            "vulnerable": vulnerable and not safe,
            "checked": vulnerable or safe,
        }
