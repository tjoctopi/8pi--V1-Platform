"""Web-shell C2 backend — a governed session over a confirmed web RCE.

Proves the Phase-D → Phase-C wire: a command-injection finding becomes a real
tracked session the FootholdRunner opens, proves (whoami/id/hostname over the web
shell), and tears down — all through the fake ToolRunner (a simulated vulnerable
endpoint that both reflects the payload AND executes it, so we prove extraction
ignores reflection).
"""

from __future__ import annotations

import re

from attack_engine.c2.foothold import FootholdRunner
from attack_engine.c2.session import Session, SessionKind, SessionManager, SessionStatus
from attack_engine.c2.webshell import WebInjectionPoint, WebShellBackend, web_shell_backend
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.findings import Finding
from attack_engine.schemas.tools import ToolProfile, ToolResult

_SENTINEL = b"\n__AEPROBE__HTTP:200 SIZE:0 TIME:0.010"
# What the simulated box returns for each command.
_OUTPUTS = {"whoami": "www-data", "id": "uid=33(www-data) gid=33(www-data)",
            "hostname": "web01", "echo ae-alive": "ae-alive"}


class _VulnRunner:
    """Simulates a shell-injection endpoint: reflects the payload AND executes it."""

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.calls: list[tuple[str, str]] = []

    def run(self, tool: str, target: str, profile: ToolProfile) -> ToolResult:
        self.calls.append((tool, target))
        inj = profile.args.get("data") or profile.args.get("params") or {}
        payload = next((v for v in inj.values() if "echo S$((" in str(v)), "")
        # Extract the command between the two echo-guards (as a real shell would run it).
        m = re.search(r"echo S\$\(\(9091\*9067\)\);\s*(.*?);\s*echo \$\(\(9067\*9091\)\)E", payload)
        cmd = m.group(1).strip() if m else ""
        reflected = f"<p>You entered: {payload}</p>"  # reflection of raw input (NOT executed)
        executed = ""
        if self.vulnerable and m:
            executed = f"<pre>lookup failed\nS82428097\n{_OUTPUTS.get(cmd, '')}\n82428097E</pre>"
        body = (reflected + executed).encode()
        return ToolResult(tool=tool, target=target, raw=body + _SENTINEL,
                          parsed={"status": 200}, exit_code=0, audit_id="aud",
                          engagement_id="eng-1")


def _session(host: str = "10.5.0.12") -> Session:
    return Session(id="sess-1", engagement_id="eng-1", host=host,
                   kind=SessionKind.SHELL, opened_at="2026-07-16T00:00:00Z")


def _injection(**kw) -> WebInjectionPoint:
    base = {"param": "target_host", "path": "/mutillidae/index.php", "method": "POST",
            "params": {"page": "dns-lookup.php"}, "data": {"submit": "Lookup DNS"}}
    base.update(kw)
    return WebInjectionPoint(**base)


def _scope() -> Scope:
    return Scope(engagement_id="eng-1", allowed_cidrs=("10.5.0.0/24",),
                 roe=RulesOfEngagement(default_rate_limit=RateLimit(requests_per_sec=1000, burst=100),
                                       autonomy_tier=2, authorized_techniques=("T1190",)),
                 authorized_by="t@8pi.ai", signature="sig")


# --- backend ---------------------------------------------------------------


def test_run_command_returns_executed_output_not_reflection() -> None:
    be = WebShellBackend(_VulnRunner(), _injection())
    assert be.run_command(_session(), "whoami") == "www-data"
    assert be.run_command(_session(), "id") == "uid=33(www-data) gid=33(www-data)"


def test_alive_true_on_vuln_false_on_patched() -> None:
    assert WebShellBackend(_VulnRunner(vulnerable=True), _injection()).alive(_session()) is True
    assert WebShellBackend(_VulnRunner(vulnerable=False), _injection()).alive(_session()) is False


def test_close_is_idempotent_and_kills_the_channel() -> None:
    be = WebShellBackend(_VulnRunner(), _injection())
    s = _session()
    be.close(s)
    be.close(s)  # idempotent
    assert be.alive(s) is False
    assert be.run_command(s, "whoami") == ""


def test_injection_point_from_finding() -> None:
    f = Finding(engagement_id="eng-1", asset="10.5.0.12", type="command-injection",
                metadata={"param": "host", "path": "/cmd", "port": 8080, "method": "GET"})
    inj = WebInjectionPoint.from_finding(f)
    assert inj.param == "host" and inj.port == 8080 and inj.method == "GET"


# --- the Phase-D -> Phase-C wire: FootholdRunner over the web shell ---------


def test_foothold_runner_establishes_session_over_web_rce() -> None:
    scope = _scope()
    audit = AuditLog()
    mgr = SessionManager(scope, audit)
    finding = Finding(engagement_id="eng-1", asset="10.5.0.12", type="command-injection",
                      metadata={"param": "target_host", "path": "/mutillidae/index.php",
                                "method": "POST", "params": {"page": "dns-lookup.php"},
                                "data": {"submit": "Lookup DNS"}})
    backend = web_shell_backend(_VulnRunner(), finding)
    runner = FootholdRunner(mgr, backend, scope, audit)  # tier-2 → autonomous, no gate needed

    foothold = runner.establish("10.5.0.12", opened_by="cmdi")
    assert foothold is not None and foothold.ok
    assert foothold.proof["whoami"] == "www-data"
    assert "www-data" in foothold.proof["id"]
    assert mgr.sessions(active_only=True)  # session tracked

    # kill-switch / teardown closes bookkeeping AND the web-shell channel
    assert runner.teardown() == 1
    assert not mgr.sessions(active_only=True)
    assert mgr.sessions()[0].status is SessionStatus.CLOSED
