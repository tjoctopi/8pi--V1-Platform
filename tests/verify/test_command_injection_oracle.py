"""Command-injection / RCE oracle — proves execution, rejects reflection.

Runs through the real Tool Runner + http_probe against sandbox doubles: a
vulnerable endpoint evaluates the injected arithmetic; a non-vuln one echoes the
payload verbatim (guards present, expression un-evaluated) and must NOT confirm.
"""

from __future__ import annotations

import urllib.parse

from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.oracles.command_injection import CommandInjectionOracle
from tests.verify.conftest import make_verify_ctx

_PRODUCT = "82428097"  # 9091 * 9067


def _probe_stdout(body: bytes, status: int = 200) -> bytes:
    return body + b"\n__AEPROBE__HTTP:%d SIZE:%d TIME:0.010" % (status, len(body))


class _CmdiSandbox(Sandbox):
    """A shell-injection endpoint (vulnerable) or one that just echoes input."""

    name = "fake-cmdi"

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable

    def run(self, spec: SandboxSpec) -> SandboxResult:
        blob = urllib.parse.unquote(" ".join(spec.argv))
        # The payload embeds a guard 'aec<hash>' and the expression '9091*9067'.
        if "aec" in blob and "9091*9067" in blob:
            # crude guard extraction: the marker starts at 'aec'
            start = blob.index("aec")
            guard = blob[start:start + 11]  # 'aec' + 8 hex chars
            if self.vulnerable:
                body = f"nslookup: {guard}{_PRODUCT}{guard}".encode()  # evaluated
            else:
                body = f"nslookup: {guard}$((9091*9067)){guard}".encode()  # echoed
            return SandboxResult(0, _probe_stdout(body), b"", 0.01, self.name)
        return SandboxResult(0, _probe_stdout(b"usage"), b"", 0.01, self.name)


def _finding() -> Finding:
    return Finding(
        engagement_id="engagement-range", asset="10.5.0.12", type="command-injection",
        metadata={"param": "target_host", "path": "/cmd", "method": "POST"},
    )


def test_rce_confirmed_when_command_executes(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _CmdiSandbox(vulnerable=True))
    result = CommandInjectionOracle().verify(_finding(), ctx)
    assert result.passed
    assert result.measurements["technique"] == "os-command-injection"
    assert _PRODUCT in result.detail


def test_rce_rejected_on_reflection(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _CmdiSandbox(vulnerable=False))
    result = CommandInjectionOracle().verify(_finding(), ctx)
    assert not result.passed


def test_rce_needs_a_param(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _CmdiSandbox())
    f = Finding(engagement_id="engagement-range", asset="10.5.0.12",
                type="command-injection", metadata={})
    assert not CommandInjectionOracle().verify(f, ctx).passed


def test_registered_and_routed() -> None:
    reg = default_oracle_registry()
    assert isinstance(reg.for_finding(_finding()), CommandInjectionOracle)
    rce = Finding(engagement_id="e", asset="a", type="rce", metadata={})
    assert isinstance(reg.for_finding(rce), CommandInjectionOracle)
