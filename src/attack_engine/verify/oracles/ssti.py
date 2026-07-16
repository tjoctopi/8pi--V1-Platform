"""SSTI impact oracle — proves server-side *template evaluation*, not a reflection.

Server-side template injection is proven the way an operator proves it by hand:
feed the app an arithmetic expression in template syntax and check whether the
*product* comes back. A reflected ``{{7*7}}`` proves nothing (it might just be
echoed); a returned ``49`` proves the server evaluated the expression — code
execution inside the template context.

To make the proof undeniable and impossible to match by coincidence we bracket a
distinctive product between two unique guard markers: we send ``<g>{{A*B}}<g>``
and confirm ``<g><A*B><g>`` appears verbatim. The literal guards reflect
unchanged while the expression between them collapses to its product — so a page
that merely echoes our input (guards present, expression *not* evaluated) fails,
and only genuine evaluation passes. We try the common engine syntaxes
(Jinja2/Twig, FreeMarker/EL, ERB/JSP). Read-only: we observe only our own marker,
never target data — weaponising the execution stays behind the human gate.
"""

from __future__ import annotations

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..context import VerifyContext
from .base import Oracle, OracleResult

#: Two large factors whose product is distinctive (8 digits, no repeats) so it
#: cannot plausibly occur by chance in a page. 9091 * 9067 = 82428097.
_A, _B = 9091, 9067
_PRODUCT = str(_A * _B)

#: Unique guards bracketing the expression — they reflect verbatim, proving the
#: collapse of the expression *between* them was evaluation, not a stray number.
_GUARD = "ae8ssti"
_EXPECTED = f"{_GUARD}{_PRODUCT}{_GUARD}"

#: Per-engine template syntaxes for ``A*B``, each wrapped in the guards.
_PAYLOADS: tuple[str, ...] = (
    f"{_GUARD}{{{{{_A}*{_B}}}}}{_GUARD}",   # {{A*B}} — Jinja2 / Twig / Nunjucks
    f"{_GUARD}${{{_A}*{_B}}}{_GUARD}",       # ${A*B}  — FreeMarker / JSP EL / Thymeleaf
    f"{_GUARD}#{{{_A}*{_B}}}{_GUARD}",       # #{A*B}  — Ruby / JSF
    f"{_GUARD}<%= {_A}*{_B} %>{_GUARD}",     # <%= A*B %> — ERB / JSP
)


class SstiOracle(Oracle):
    oracle_id = "ssti_oracle_v1"

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith(("ssti", "template-injection"))

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        if not param:
            return OracleResult(
                passed=False, oracle_id=self.oracle_id,
                detail="finding lacks an injection param in metadata",
            )
        method = str(md.get("method", "GET")).upper()
        payload_key = "data" if method in ("POST", "PUT") else "params"
        base_args = {"scheme": md.get("scheme", "http"), "port": md.get("port"),
                     "path": md.get("path", "/"), "method": method}
        evidence: list[str] = []

        for payload in _PAYLOADS:
            profile = ToolProfile(args={**base_args, payload_key: {str(param): payload}})
            result = ctx.tool_runner.run("http_probe", finding.asset, profile)
            evidence.append(f"raw:{result.audit_id}")
            if HttpProbeWrapper.body_contains(result.raw, _EXPECTED):
                return OracleResult(
                    passed=True, oracle_id=self.oracle_id,
                    detail=(
                        f"template evaluated {_A}*{_B}={_PRODUCT} in param "
                        f"'{param}' (status {result.parsed.get('status')}) — SSTI proven"
                    ),
                    confidence=0.98, evidence=tuple(evidence),
                    measurements={"technique": "ssti", "param": str(param), "payload": payload},
                )
        return OracleResult(
            passed=False, oracle_id=self.oracle_id,
            detail=(
                f"expression not evaluated in '{param}' across "
                f"{len(_PAYLOADS)} template syntaxes"
            ),
            evidence=tuple(evidence),
        )
