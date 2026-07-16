"""SSTI impact oracle — proves template *evaluation*, rejects mere reflection.

Runs through the real Tool Runner + http_probe against sandbox doubles: a
vulnerable engine collapses the guarded expression to its product; a non-vuln
app echoes the payload verbatim (guards present, expression un-evaluated) and
must NOT confirm.
"""

from __future__ import annotations

import urllib.parse

from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.oracles.ssti import SstiOracle
from tests.verify.conftest import make_verify_ctx

_GUARD = "ae8ssti"
_PRODUCT = "82428097"  # 9091 * 9067
_EXPR = "9091*9067"


def _probe_stdout(body: bytes, status: int = 200) -> bytes:
    return body + b"\n__AEPROBE__HTTP:%d SIZE:%d TIME:0.010" % (status, len(body))


class _SstiSandbox(Sandbox):
    """Renders the injected value through a template — or just echoes it."""

    name = "fake-ssti"

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable

    def run(self, spec: SandboxSpec) -> SandboxResult:
        url = urllib.parse.unquote(spec.argv[-1] if spec.argv else "")
        if _GUARD in url and _EXPR in url:
            if self.vulnerable:
                body = f"<h1>Hi {_GUARD}{_PRODUCT}{_GUARD}</h1>".encode()  # evaluated
            else:
                body = f"<h1>Hi {_GUARD}{_EXPR}{_GUARD}</h1>".encode()  # echoed verbatim
        else:
            body = b"<html>home</html>"
        return SandboxResult(0, _probe_stdout(body), b"", 0.01, self.name)


def _finding() -> Finding:
    return Finding(
        engagement_id="engagement-range", asset="10.5.0.20", type="ssti",
        metadata={"param": "name", "path": "/greet", "method": "GET"},
    )


def test_ssti_confirmed_when_expression_evaluates(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _SstiSandbox(vulnerable=True))
    result = SstiOracle().verify(_finding(), ctx)
    assert result.passed
    assert result.measurements["technique"] == "ssti"
    assert _PRODUCT in result.detail


def test_ssti_rejected_on_mere_reflection(scope: Scope, audit: AuditLog) -> None:
    # Guards + payload reflect, but the expression is NOT evaluated → not SSTI.
    ctx = make_verify_ctx(scope, audit, _SstiSandbox(vulnerable=False))
    result = SstiOracle().verify(_finding(), ctx)
    assert not result.passed


def test_ssti_needs_a_param(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _SstiSandbox())
    f = Finding(engagement_id="engagement-range", asset="10.5.0.20", type="ssti", metadata={})
    result = SstiOracle().verify(f, ctx)
    assert not result.passed and "param" in result.detail


def test_ssti_oracle_registered_and_routed() -> None:
    reg = default_oracle_registry()
    assert reg.for_finding(_finding()) is not None
    assert isinstance(reg.for_finding(_finding()), SstiOracle)
