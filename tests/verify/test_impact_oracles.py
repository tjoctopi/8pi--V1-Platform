"""Impact oracles — LFI file-read and SSRF-via-OOB.

Unlike the signal oracles, these prove *impact*: an actual file read, and an
actual attacker-dictated outbound request. They run through the real Tool Runner
and http_probe against sandbox doubles that simulate a vulnerable target.
"""

from __future__ import annotations

import re
import urllib.parse

from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.oob import InMemoryOobServer
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.oracles.lfi_file_read import LfiFileReadOracle
from attack_engine.verify.oracles.ssrf_oob import SsrfOobOracle
from tests.verify.conftest import make_verify_ctx

_PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _probe_stdout(body: bytes, status: int = 200) -> bytes:
    """Mimic the http_probe curl output: body + write-out sentinel line."""

    return body + b"\n__AEPROBE__HTTP:%d SIZE:%d TIME:0.010" % (status, len(body))


class _LfiSandbox(Sandbox):
    name = "fake-lfi"

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable

    def run(self, spec: SandboxSpec) -> SandboxResult:
        url = urllib.parse.unquote(spec.argv[-1] if spec.argv else "").lower()
        wants_passwd = "etc/passwd" in url
        body = _PASSWD if (self.vulnerable and wants_passwd) else b"<html>404 not found</html>"
        return SandboxResult(0, _probe_stdout(body), b"", 0.01, self.name)


class _SsrfSandbox(Sandbox):
    """Simulates a server that (when vulnerable) fetches the URL it is given."""

    name = "fake-ssrf"
    _OOB_RE = re.compile(r"https?://([a-z0-9.-]+\.oob\.8pi-range\.test)")

    def __init__(self, oob: InMemoryOobServer, vulnerable: bool = True) -> None:
        self.oob = oob
        self.vulnerable = vulnerable

    def run(self, spec: SandboxSpec) -> SandboxResult:
        url = urllib.parse.unquote(spec.argv[-1] if spec.argv else "")
        if self.vulnerable:
            m = self._OOB_RE.search(url)
            if m:
                self.oob.record_hostname(m.group(1), "http", source_ip="10.5.0.20")
        return SandboxResult(0, _probe_stdout(b"ok"), b"", 0.01, self.name)


def _finding(ftype: str, **metadata) -> Finding:
    return Finding(
        engagement_id="engagement-range",
        asset="10.5.0.10",
        type=ftype,
        metadata=metadata,
    )


# --- LFI ------------------------------------------------------------------------


def test_lfi_confirms_file_read_via_param(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _LfiSandbox(vulnerable=True))
    finding = _finding("lfi", param="file")
    result = LfiFileReadOracle().verify(finding, ctx)
    assert result.passed
    assert result.confidence >= 0.95
    assert result.measurements["technique"] == "file-read"


def test_lfi_confirms_path_traversal_without_param(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _LfiSandbox(vulnerable=True))
    result = LfiFileReadOracle().verify(_finding("path-traversal"), ctx)
    assert result.passed  # payload goes in the URL path


def test_lfi_rejects_when_no_file_signature(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _LfiSandbox(vulnerable=False))
    result = LfiFileReadOracle().verify(_finding("lfi", param="file"), ctx)
    assert not result.passed
    assert "no target-file signature" in result.detail


# --- SSRF -----------------------------------------------------------------------


def test_ssrf_confirmed_by_oob_callback(scope: Scope, audit: AuditLog) -> None:
    oob = InMemoryOobServer()
    ctx = make_verify_ctx(scope, audit, _SsrfSandbox(oob, vulnerable=True))
    ctx.oob = oob
    result = SsrfOobOracle().verify(_finding("ssrf", param="url"), ctx)
    assert result.passed
    assert result.confidence >= 0.95
    assert result.measurements["interactions"] >= 1


def test_ssrf_rejected_without_callback(scope: Scope, audit: AuditLog) -> None:
    oob = InMemoryOobServer()
    ctx = make_verify_ctx(scope, audit, _SsrfSandbox(oob, vulnerable=False))
    ctx.oob = oob
    result = SsrfOobOracle().verify(_finding("ssrf", param="url"), ctx)
    assert not result.passed
    assert "no OOB callback" in result.detail


def test_ssrf_declines_without_oob_server(scope: Scope, audit: AuditLog) -> None:
    ctx = make_verify_ctx(scope, audit, _SsrfSandbox(InMemoryOobServer()))  # ctx.oob stays None
    result = SsrfOobOracle().verify(_finding("ssrf", param="url"), ctx)
    assert not result.passed
    assert "unavailable" in result.detail


def test_ssrf_rejects_missing_param(scope: Scope, audit: AuditLog) -> None:
    oob = InMemoryOobServer()
    ctx = make_verify_ctx(scope, audit, _SsrfSandbox(oob))
    ctx.oob = oob
    result = SsrfOobOracle().verify(_finding("ssrf"), ctx)
    assert not result.passed
    assert "injection param" in result.detail


# --- registry -------------------------------------------------------------------


def test_registry_routes_impact_findings() -> None:
    reg = default_oracle_registry()
    assert isinstance(reg.for_finding(_finding("lfi")), LfiFileReadOracle)
    assert isinstance(reg.for_finding(_finding("ssrf")), SsrfOobOracle)


def test_lfi_end_to_end_verifier_promotes_to_verified(scope: Scope, audit: AuditLog) -> None:
    # Through the real Verifier: a proposed LFI becomes VERIFIED with impact proof.
    from attack_engine.schemas.findings import FindingState
    from attack_engine.verify.verifier import Verifier

    ctx = make_verify_ctx(scope, audit, _LfiSandbox(vulnerable=True))
    ctx.store.propose_finding(_finding("lfi", param="file"))
    report = Verifier(default_oracle_registry(), ctx).run()
    assert report.verified == 1
    verified = ctx.store.findings(FindingState.VERIFIED)[0]
    assert verified.exploit_prob is not None  # scored because lfi is a vuln type
