"""SSRF impact oracle — proves a *forced outbound request* via out-of-band callback.

Server-side request forgery is usually blind: the response reveals nothing, but
the vulnerable server can be made to reach an attacker-controlled endpoint. This
oracle mints a unique OOB token, plants its URL in the suspected parameter, sends
the request through the scope-enforced probe, and confirms *only* if the target
actually calls back on that exact token. A callback is undeniable proof the
server issued the request we dictated — and the unguessable token means an
unrelated hit can never forge the proof.

If no OOB server is wired (``ctx.oob is None``) the oracle declines to confirm
rather than guess (rule #1) — a blind class we cannot prove is not "confirmed".
SSRF is the first rung of a classic chain (→ cloud metadata → credentials), so
proving it is high-value; weaponising it stays behind the human gate.
"""

from __future__ import annotations

from typing import Any

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ..context import VerifyContext
from .base import Oracle, OracleResult


class SsrfOobOracle(Oracle):
    oracle_id = "ssrf_oob_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(("ssrf",))

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        if ctx.oob is None:
            return OracleResult(
                passed=False,
                oracle_id=self.oracle_id,
                detail="OOB interaction server unavailable; cannot prove blind SSRF",
            )
        md = finding.metadata
        param = md.get("param")
        if not param:
            return OracleResult(
                passed=False,
                oracle_id=self.oracle_id,
                detail="finding lacks an injection param in metadata",
            )

        token = ctx.oob.mint(f"ssrf {finding.id}")
        method = str(md.get("method", "GET")).upper()
        key = "data" if method in ("POST", "PUT") else "params"
        args: dict[str, Any] = {
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": method,
            key: {str(param): token.http_url},
        }
        result = ctx.tool_runner.run("http_probe", finding.asset, ToolProfile(args=args))
        evidence = (f"raw:{result.audit_id}",)

        hits = ctx.oob.interactions(token.token)
        if hits:
            return OracleResult(
                passed=True,
                oracle_id=self.oracle_id,
                detail=(
                    f"target fetched OOB callback via param {str(param)!r} "
                    f"({len(hits)} interaction(s)) — SSRF proven"
                ),
                confidence=0.99,
                evidence=evidence + tuple(f"oob:{h.kind}:{h.token}" for h in hits),
                measurements={
                    "technique": "ssrf-oob",
                    "token": token.token,
                    "interactions": len(hits),
                },
            )
        return OracleResult(
            passed=False,
            oracle_id=self.oracle_id,
            detail="no OOB callback observed; SSRF not proven",
            evidence=evidence,
            measurements={"token": token.token},
        )
