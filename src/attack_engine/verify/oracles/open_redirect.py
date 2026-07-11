"""Open-redirect oracle (read-only confirmation).

Confirms an open redirect deterministically: it sets the candidate parameter to
a unique, off-site marker URL and checks whether the immediate response is a
redirect (3xx) whose ``Location`` points at the attacker-controlled marker host
(or a meta/JS redirect echoing it). Redirects are **not** followed and no target
data is read — we observe only the response's own control metadata, so this is
safe read-only detection. Weaponisation (phishing / OAuth-token theft / SSRF
filter-bypass chaining) stays gated.
"""

from __future__ import annotations

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..context import VerifyContext
from .base import Oracle, OracleResult

#: Off-site marker host we should never legitimately redirect to.
_MARKER_HOST = "ae-oob-redirect.example"
_PAYLOAD = f"https://{_MARKER_HOST}/ae"
_REDIRECT_CODES = {301, 302, 303, 307, 308}


class OpenRedirectOracle(Oracle):
    oracle_id = "open_redirect_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(("open-redirect", "redirect-candidate"))

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        if not param:
            return OracleResult(
                passed=False, oracle_id=self.oracle_id,
                detail="finding lacks a redirect parameter in metadata",
            )
        profile = ToolProfile(args={
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": str(md.get("method", "GET")).upper(),
            "include_headers": True,  # need the Location header to confirm
            "params": {str(param): _PAYLOAD},
        })
        result = ctx.tool_runner.run("http_probe", finding.asset, profile)
        status = result.parsed.get("status")
        # The marker host appears in the response control metadata (Location /
        # meta-refresh / JS location) — i.e. the app will send a user off-site.
        points_offsite = HttpProbeWrapper.body_contains(result.raw, _MARKER_HOST)
        evidence = (f"raw:{result.audit_id}",)
        is_redirect = isinstance(status, int) and status in _REDIRECT_CODES
        if points_offsite and is_redirect:
            return OracleResult(
                passed=True, oracle_id=self.oracle_id,
                detail=f"parameter '{param}' redirects off-site to {_MARKER_HOST} "
                       f"(HTTP {status})",
                confidence=0.95, evidence=evidence,
                measurements={"technique": "open-redirect", "param": str(param),
                              "status": status},
            )
        return OracleResult(
            passed=False, oracle_id=self.oracle_id,
            detail=f"no off-site redirect via '{param}' (status {status})",
            evidence=evidence,
        )
