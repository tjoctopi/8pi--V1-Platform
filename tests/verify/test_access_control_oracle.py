"""Access-control oracle — proves broken authz by authorized-vs-anonymous diff.

Runs through the real Tool Runner + http_probe against a sandbox double: when the
control is broken the anonymous request gets the same protected bytes as the
authorized one; when enforced, anonymous is denied and the digests diverge.
"""

from __future__ import annotations

from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.oracles.access_control import AccessControlOracle
from tests.verify.conftest import make_verify_ctx

_PROTECTED = b"<h1>Account 1002 balance $500</h1>"


def _probe_stdout(body: bytes, status: int = 200) -> bytes:
    return body + b"\n__AEPROBE__HTTP:%d SIZE:%d TIME:0.010" % (status, len(body))


class _AuthzSandbox(Sandbox):
    """Serves protected content; ``enforced`` decides if anonymous is denied."""

    name = "fake-authz"

    def __init__(self, enforced: bool = False) -> None:
        self.enforced = enforced

    def run(self, spec: SandboxSpec) -> SandboxResult:
        has_auth = "-u" in spec.argv
        if has_auth or not self.enforced:
            return SandboxResult(0, _probe_stdout(_PROTECTED, 200), b"", 0.01, self.name)
        return SandboxResult(0, _probe_stdout(b"<h1>401 login</h1>", 401), b"", 0.01, self.name)


def _finding(**md_extra: object) -> Finding:
    md: dict[str, object] = {"auth": "alice:pw", "path": "/account", "method": "GET"}
    md.update(md_extra)
    return Finding(engagement_id="engagement-range", asset="10.5.0.20",
                   type="broken-authz", metadata=md)


def test_broken_access_control_confirmed(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _AuthzSandbox(enforced=False))
    result = AccessControlOracle().verify(_finding(), ctx)
    assert result.passed
    assert result.measurements["content_match"] is True
    assert result.measurements["anon_status"] == 200


def test_enforced_control_not_confirmed(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _AuthzSandbox(enforced=True))
    result = AccessControlOracle().verify(_finding(), ctx)
    assert not result.passed
    assert result.measurements["anon_status"] == 401


def test_declines_without_a_credential(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _AuthzSandbox())
    f = Finding(engagement_id="engagement-range", asset="10.5.0.20",
                type="broken-authz", metadata={"path": "/account"})
    result = AccessControlOracle().verify(f, ctx)
    assert not result.passed and "credential" in result.detail


def test_registered_and_routes_idor_and_authz() -> None:
    reg = default_oracle_registry()
    idor = Finding(engagement_id="e", asset="a", type="idor", metadata={})
    authz = Finding(engagement_id="e", asset="a", type="broken-authz", metadata={})
    assert isinstance(reg.for_finding(idor), AccessControlOracle)
    assert isinstance(reg.for_finding(authz), AccessControlOracle)
