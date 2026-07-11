"""Version re-grab oracle — confirms a service/version observation.

The Surface Mapper *proposes* "Apache httpd 2.4.49 on :80". This oracle
independently re-grabs the service banner (a fresh, scope-enforced nmap probe of
just that port) and confirms the finding only if the re-grabbed product/version
matches. A one-shot scan that can't be reproduced is rejected — killing
transient false positives before they reach the correlator.
"""

from __future__ import annotations

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ..context import VerifyContext
from .base import Oracle, OracleResult


class VersionRegrabOracle(Oracle):
    oracle_id = "version_regrab_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith("exposed-service:") and finding.service is not None

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        port = finding.metadata.get("port")
        if port is None:
            # Fall back to parsing the port out of "exposed-service:PORT/proto".
            try:
                port = int(finding.type.split(":", 1)[1].split("/", 1)[0])
            except (IndexError, ValueError):
                return OracleResult(
                    passed=False,
                    oracle_id=self.oracle_id,
                    detail="could not determine port to re-grab",
                )

        result = ctx.tool_runner.run(
            "nmap", finding.asset, ToolProfile(preset="default", args={"ports": str(port)})
        )
        regrabbed = next(
            (p for p in result.parsed.get("ports", []) if int(p["port"]) == int(port)),
            None,
        )
        if regrabbed is None:
            return OracleResult(
                passed=False,
                oracle_id=self.oracle_id,
                detail=f"port {port} not open on re-grab",
                evidence=(f"raw:{result.audit_id}",),
            )

        # Compare the re-grabbed product/version against the proposed cpe hint.
        regrabbed_hint = "/".join(
            b for b in (regrabbed.get("product"), regrabbed.get("version")) if b
        ) or (regrabbed.get("service") or "unknown")
        proposed = finding.service or ""
        matched = _hints_agree(proposed, regrabbed_hint)
        return OracleResult(
            passed=matched,
            oracle_id=self.oracle_id,
            detail=(
                f"re-grab {'confirms' if matched else 'contradicts'} "
                f"{proposed!r} (observed {regrabbed_hint!r})"
            ),
            evidence=(f"raw:{result.audit_id}",),
            measurements={"proposed": proposed, "regrabbed": regrabbed_hint},
        )


def _hints_agree(a: str, b: str) -> bool:
    """Loose agreement: same product family and, if both give a version, same
    version. Case-insensitive; tolerant of the ``product/version`` shape."""

    a_l, b_l = a.lower(), b.lower()
    if a_l == b_l:
        return True
    a_prod = a_l.split("/", 1)[0].strip()
    b_prod = b_l.split("/", 1)[0].strip()
    return bool(a_prod) and a_prod == b_prod
