"""Wrapper tests for the expanded toolset (masscan/httpx/katana/dalfox/msf)."""

from __future__ import annotations

import pytest

from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import SandboxResult
from attack_engine.toolrunner.wrappers.dalfox import DalfoxWrapper
from attack_engine.toolrunner.wrappers.httpx import HttpxWrapper
from attack_engine.toolrunner.wrappers.katana import KatanaWrapper
from attack_engine.toolrunner.wrappers.masscan import MasscanWrapper
from attack_engine.toolrunner.wrappers.metasploit import MetasploitCheckWrapper


def _res(stdout: bytes) -> SandboxResult:
    return SandboxResult(0, stdout, b"", 0.01, "fake")


def test_all_new_tools_registered() -> None:
    names = set(default_registry().names())
    assert {"masscan", "httpx", "katana", "dalfox", "metasploit_check"} <= names


class TestMasscan:
    def test_argv_read_only(self) -> None:
        w = MasscanWrapper()
        argv = w.build_argv("10.5.0.10", ToolProfile(args={"ports": "80,443", "rate": "500"}))
        assert argv[:2] == ["masscan", "10.5.0.10"]
        assert "-oJ" in argv
        assert w.is_mutating(ToolProfile()) is False

    def test_parse_open_ports(self) -> None:
        raw = b'[{"ip":"10.5.0.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}]'
        parsed = MasscanWrapper().parse("10.5.0.10", _res(raw))
        assert parsed["ports"] == [{"port": 80, "protocol": "tcp", "state": "open"}]

    def test_parse_trailing_comma_tolerated(self) -> None:
        raw = b'{"ip":"10.5.0.10","ports":[{"port":22,"proto":"tcp","status":"open"}]},'
        parsed = MasscanWrapper().parse("10.5.0.10", _res(raw))
        assert parsed["ports"][0]["port"] == 22


class TestHttpx:
    def test_parse_jsonl(self) -> None:
        raw = (
            b'{"url":"http://10.5.0.10","status_code":200,"title":"Home",'
            b'"webserver":"Apache/2.4.49","tech":["Apache","PHP"]}\n'
        )
        parsed = HttpxWrapper().parse("10.5.0.10", _res(raw))
        assert parsed["results"][0]["webserver"] == "Apache/2.4.49"
        assert "Apache" in parsed["results"][0]["tech"]


class TestKatana:
    def test_parse_endpoints_with_params(self) -> None:
        raw = (
            b'{"endpoint":"http://10.5.0.10/search?q=1&cat=2"}\n'
            b'{"endpoint":"http://10.5.0.10/about"}\n'
        )
        parsed = KatanaWrapper().parse("10.5.0.10", _res(raw))
        search = next(e for e in parsed["endpoints"] if e["path"] == "/search")
        assert "q" in search["params"] and "cat" in search["params"]

    def test_argv_extracts_forms(self) -> None:
        # -fx/-aff make katana surface POST forms — the injection points (e.g. a
        # dns-lookup form's target_host) a plain crawl never sees.
        argv = KatanaWrapper().build_argv("10.5.0.12", ToolProfile())
        assert "-fx" in argv and "-aff" in argv

    def test_parse_post_form_fields(self) -> None:
        # A filled POST form (katana -fx -aff): the body names each field, which
        # become injectable candidates with their companions as fixed context.
        raw = (
            b'{"request":{"method":"POST",'
            b'"endpoint":"http://10.5.0.12/mutillidae/index.php?page=dns-lookup.php",'
            b'"body":"target_host=katana&dns-lookup-php-submit-button=Lookup+DNS"}}\n'
        )
        parsed = KatanaWrapper().parse("10.5.0.12", _res(raw))
        form_ep = next(e for e in parsed["endpoints"] if e["method"] == "POST")
        assert form_ep["form"]["target_host"] == "katana"
        assert form_ep["form"]["dns-lookup-php-submit-button"] == "Lookup DNS"
        assert form_ep["params"] == ["page"]


class TestDalfox:
    def test_parse_findings(self) -> None:
        raw = b'[{"param":"q","inject_type":"inHTML","method":"GET","evidence":"<script>"}]'
        parsed = DalfoxWrapper().parse("10.5.0.10", _res(raw))
        assert parsed["findings"][0]["param"] == "q"


class TestMetasploitCheckOnly:
    def test_is_mutating_so_read_only_roe_blocks_it(self) -> None:
        assert MetasploitCheckWrapper().is_mutating(ToolProfile()) is True

    def test_builds_check_action_only(self) -> None:
        argv = MetasploitCheckWrapper().build_argv(
            "10.5.0.10", ToolProfile(args={"module": "exploit/x", "port": 80})
        )
        resource = argv[-1]
        assert "check" in resource
        assert "exploit/x" in resource
        # No exploitation verbs may appear in the resource script.
        assert " exploit;" not in resource and "run;" not in resource

    def test_forbids_exploitation_actions(self) -> None:
        with pytest.raises(ValueError, match="forbidden"):
            MetasploitCheckWrapper().build_argv(
                "10.5.0.10", ToolProfile(args={"module": "exploit/x", "actions": ["exploit"]})
            )

    def test_requires_module(self) -> None:
        with pytest.raises(ValueError, match="module"):
            MetasploitCheckWrapper().build_argv("10.5.0.10", ToolProfile())

    def test_parse_vulnerable(self) -> None:
        parsed = MetasploitCheckWrapper().parse(
            "10.5.0.10", _res(b"[+] 10.5.0.10:80 - The target is vulnerable.")
        )
        assert parsed["vulnerable"] is True

    def test_parse_not_vulnerable(self) -> None:
        parsed = MetasploitCheckWrapper().parse(
            "10.5.0.10", _res(b"[-] 10.5.0.10:80 - The target is not vulnerable.")
        )
        assert parsed["vulnerable"] is False
        assert parsed["checked"] is True


class TestKerberoast:
    def test_parse_emits_hashes_and_accounts(self) -> None:
        from attack_engine.toolrunner.wrappers.kerberoast import KerberoastWrapper

        tgs = "$krb5tgs$23$*svc_sql*CORP.LOCAL*MSSQL/db*$abcd$ef01"
        parsed = KerberoastWrapper().parse("10.5.0.20", _res(tgs.encode()))
        assert parsed["roastable"] is True
        assert parsed["hash_count"] == 1
        assert parsed["hashes"] == [tgs]
        assert parsed["accounts"] == ["svc_sql@CORP.LOCAL"]

    def test_principal_of_tgs_and_asrep(self) -> None:
        from attack_engine.toolrunner.wrappers.kerberoast import principal_of

        assert principal_of("$krb5tgs$23$*svc_sql*CORP.LOCAL*x*$a$b") == "svc_sql@CORP.LOCAL"
        assert principal_of("$krb5asrep$23$alice@CORP.LOCAL:a$b") == "alice@CORP.LOCAL"
        assert principal_of("garbage") is None

    def test_parse_empty_when_no_hashes(self) -> None:
        from attack_engine.toolrunner.wrappers.kerberoast import KerberoastWrapper

        parsed = KerberoastWrapper().parse("10.5.0.20", _res(b"no tickets here"))
        assert parsed["roastable"] is False
        assert parsed["hashes"] == []
        assert parsed["accounts"] == []
