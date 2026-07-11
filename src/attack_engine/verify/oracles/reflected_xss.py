"""Reflected-XSS oracle (read-only confirmation).

Confirms a reflected cross-site-scripting point *deterministically and safely*:
it injects a unique, benign marker containing HTML-significant characters and
checks whether the marker is reflected **verbatim (unencoded)** in the response.
If the app echoes ``"><svg…`` unescaped, the input reaches the HTML sink without
encoding — the defining condition for reflected XSS. Nothing executes; we only
observe our *own* marker (never target data), so this is safe read-only
detection, not exploitation (weaponisation stays gated).
"""

from __future__ import annotations

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..context import VerifyContext
from .base import Oracle, OracleResult

#: Unique, non-executing marker with the characters that must survive unencoded
#: for reflected XSS to be possible (angle brackets + quote + slash).
_MARKER = 'ae7xq9zK"><svg/ae'


class ReflectedXssOracle(Oracle):
    oracle_id = "reflected_xss_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(("xss-reflected", "xss-candidate", "xss"))

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        if not param:
            return OracleResult(
                passed=False, oracle_id=self.oracle_id,
                detail="finding lacks a reflected parameter in metadata",
            )
        method = str(md.get("method", "GET")).upper()
        payload_key = "data" if method in ("POST", "PUT") else "params"
        profile = ToolProfile(args={
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": method,
            payload_key: {str(param): _MARKER},
        })
        result = ctx.tool_runner.run("http_probe", finding.asset, profile)
        reflected = HttpProbeWrapper.body_contains(result.raw, _MARKER)
        evidence = (f"raw:{result.audit_id}",)
        if reflected:
            return OracleResult(
                passed=True, oracle_id=self.oracle_id,
                detail=f"marker reflected unencoded in parameter '{param}' "
                       f"(status {result.parsed.get('status')})",
                confidence=0.95, evidence=evidence,
                measurements={"technique": "reflected-xss", "param": str(param)},
            )
        return OracleResult(
            passed=False, oracle_id=self.oracle_id,
            detail=f"marker not reflected unencoded in '{param}' (encoded or absent)",
            evidence=evidence,
        )
