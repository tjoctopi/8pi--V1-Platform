"""Read-only confirmation oracles: reflected-XSS, open-redirect, POST SQLi."""

from __future__ import annotations

from attack_engine.schemas.findings import Finding
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.oracles.open_redirect import _MARKER_HOST, OpenRedirectOracle
from attack_engine.verify.oracles.reflected_xss import _MARKER, ReflectedXssOracle
from attack_engine.verify.oracles.sqli_boolean_blind import SqliBooleanBlindOracle

from .conftest import make_verify_ctx


def _probe_out(body: bytes, status: int = 200) -> bytes:
    return body + b"\n__AEPROBE__HTTP:%d SIZE:%d TIME:0.01" % (status, len(body))


class _XssSandbox(Sandbox):
    name = "xss"

    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.calls: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        # Vulnerable: reflects the marker verbatim (unencoded). Safe: HTML-encodes it.
        inner = _MARKER.encode() if self.vulnerable else b"ae7xq9zK&quot;&gt;&lt;svg"
        return SandboxResult(0, _probe_out(b"<html>" + inner + b"</html>"), b"", 0.01, self.name)


class _RedirectSandbox(Sandbox):
    name = "redir"

    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.calls: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        if self.vulnerable:
            body = (b"HTTP/1.1 302 Found\r\nLocation: https://" + _MARKER_HOST.encode()
                    + b"/ae\r\n\r\n")
            return SandboxResult(0, _probe_out(body, status=302), b"", 0.01, self.name)
        return SandboxResult(0, _probe_out(b"HTTP/1.1 200 OK\r\n\r\nok"), b"", 0.01, self.name)


class _PostSqliSandbox(Sandbox):
    name = "postsqli"

    def __init__(self) -> None:
        self.calls: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        argv = " ".join(spec.argv)
        # The TRUE-condition payload ('1'='1) lands in the POST body (argv), not the URL.
        true_cond = "%271%27%3D%271" in argv or "1'='1" in argv
        size = 5120 if true_cond else 128
        return SandboxResult(0, b"HTTP:200 SIZE:%d TIME:0.01" % size, b"", 0.01, self.name)


class TestReflectedXssOracle:
    def test_confirms_unencoded_reflection(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, _XssSandbox(vulnerable=True))
        f = Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                    type="xss-candidate", metadata={"port": 80, "path": "/s", "param": "q"})
        result = ReflectedXssOracle().verify(f, ctx)
        assert result.passed is True
        assert result.measurements["technique"] == "reflected-xss"

    def test_rejects_encoded_output(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, _XssSandbox(vulnerable=False))
        f = Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                    type="xss-candidate", metadata={"port": 80, "path": "/s", "param": "q"})
        assert ReflectedXssOracle().verify(f, ctx).passed is False


class TestOpenRedirectOracle:
    def test_confirms_offsite_redirect(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, _RedirectSandbox(vulnerable=True))
        f = Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                    type="open-redirect-candidate",
                    metadata={"port": 80, "path": "/redirect", "param": "to"})
        result = OpenRedirectOracle().verify(f, ctx)
        assert result.passed is True
        assert result.measurements["status"] == 302
        # The probe requested response headers (needed to see Location).
        assert any("-i" in c.argv for c in ctx.tool_runner._sandbox.calls)  # type: ignore[attr-defined]

    def test_rejects_same_site_200(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, _RedirectSandbox(vulnerable=False))
        f = Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                    type="open-redirect-candidate",
                    metadata={"port": 80, "path": "/redirect", "param": "to"})
        assert OpenRedirectOracle().verify(f, ctx).passed is False


class TestSqliPostMethod:
    def test_confirms_sqli_in_post_body_param(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, _PostSqliSandbox())
        f = Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                    type="sqli-boolean-blind",
                    metadata={"port": 80, "path": "/login", "param": "user",
                              "base_value": "admin", "method": "POST"})
        result = SqliBooleanBlindOracle().verify(f, ctx)
        assert result.passed is True
        # The payload was sent as POST data, not a query string.
        assert any("--data-urlencode" in c.argv for c in ctx.tool_runner._sandbox.calls)  # type: ignore[attr-defined]
