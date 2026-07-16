"""Access-control oracle — proves a protected resource is served *without* authority.

Broken access control (missing function-level authz / IDOR / BOLA) is proven by
comparison, not by a single response: fetch the resource with a valid credential
(the authorized baseline) and again with **no credential**, and confirm the
control is broken only if the unauthenticated request returns the *same protected
content* — byte-identical by digest — with a success status. If the app enforces
the control, the anonymous request is denied (or served a different login/error
body) and the digests diverge, so nothing is confirmed.

We compare only SHA-256 digests of the two responses (the http_probe wrapper
never surfaces bodies), so this reads no target data — it observes that identical
protected bytes were returned to an unauthorized caller. The finding must carry
the authorized credential (``basic_auth``) that establishes the baseline; without
it the oracle declines rather than guess (rule #1). Weaponising the access stays
behind the human gate.
"""

from __future__ import annotations

from typing import Any

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ..context import VerifyContext
from .base import Oracle, OracleResult


class AccessControlOracle(Oracle):
    oracle_id = "access_control_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(
            ("broken-authz", "access-control", "auth-bypass", "idor", "bola")
        )

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        auth = md.get("auth") or md.get("basic_auth")
        if not auth:
            return OracleResult(
                passed=False, oracle_id=self.oracle_id,
                detail="no authorized credential (basic_auth) to establish the protected baseline",
            )
        method = str(md.get("method", "GET")).upper()
        base_args: dict[str, Any] = {
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": method,
        }
        if md.get("params"):
            base_args["params"] = md["params"]

        authed = ctx.tool_runner.run(
            "http_probe", finding.asset, ToolProfile(args={**base_args, "basic_auth": str(auth)})
        )
        anon = ctx.tool_runner.run(
            "http_probe", finding.asset, ToolProfile(args=dict(base_args))
        )
        evidence = (f"raw:{authed.audit_id}", f"raw:{anon.audit_id}")

        authed_status = authed.parsed.get("status")
        anon_status = anon.parsed.get("status")
        authed_hash = authed.parsed.get("body_sha256")
        anon_hash = anon.parsed.get("body_sha256")

        baseline_ok = isinstance(authed_status, int) and 200 <= authed_status < 300
        anon_ok = isinstance(anon_status, int) and 200 <= anon_status < 300
        same_content = bool(authed_hash) and authed_hash == anon_hash

        if baseline_ok and anon_ok and same_content:
            return OracleResult(
                passed=True, oracle_id=self.oracle_id,
                detail=(
                    f"protected resource {base_args['path']!r} returned identical content "
                    f"(status {anon_status}) with NO credential — access control not enforced"
                ),
                confidence=0.97, evidence=evidence,
                measurements={
                    "technique": "broken-access-control",
                    "authed_status": authed_status,
                    "anon_status": anon_status,
                    "content_match": True,
                },
            )
        reason = (
            "authorized baseline was not a 2xx protected response"
            if not baseline_ok
            else "anonymous request was denied or served different content"
        )
        return OracleResult(
            passed=False, oracle_id=self.oracle_id,
            detail=f"access control appears enforced: {reason}",
            evidence=evidence,
            measurements={"authed_status": authed_status, "anon_status": anon_status},
        )
