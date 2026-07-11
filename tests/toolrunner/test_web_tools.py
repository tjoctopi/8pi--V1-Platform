"""Wrapper tests for Sprint 1 web/exploit tools + the HTTP probe."""

from __future__ import annotations

import pytest

from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.sandbox import SandboxResult
from attack_engine.toolrunner.wrappers.http_probe import HttpProbeWrapper
from attack_engine.toolrunner.wrappers.nikto import NiktoWrapper
from attack_engine.toolrunner.wrappers.nuclei import NucleiWrapper
from attack_engine.toolrunner.wrappers.sqlmap import SqlmapConfirmWrapper
from attack_engine.toolrunner.wrappers.wpscan import WpscanWrapper


def _res(stdout: bytes) -> SandboxResult:
    return SandboxResult(0, stdout, b"", 0.01, "fake")


class TestHttpProbe:
    def test_builds_url_with_encoded_params(self) -> None:
        argv = HttpProbeWrapper().build_argv(
            "10.5.0.10",
            ToolProfile(args={"scheme": "http", "port": 3000, "path": "/search",
                              "params": {"q": "a' AND '1'='1"}}),
        )
        url = argv[-1]
        assert url.startswith("http://10.5.0.10:3000/search?q=")
        assert "%27" in url  # the quote was URL-encoded (never shell-exposed)
        assert "-w" in argv  # write-out template drives status/size/time capture

    def test_parse_writeout(self) -> None:
        parsed = HttpProbeWrapper().parse("10.5.0.10", _res(b"HTTP:200 SIZE:5120 TIME:0.031"))
        assert parsed["status"] == 200
        assert parsed["size"] == 5120
        assert parsed["time"] == 0.031

    def test_parse_garbage_flags_error(self) -> None:
        parsed = HttpProbeWrapper().parse("10.5.0.10", _res(b"connection refused"))
        assert parsed.get("parse_error") is True


class TestNuclei:
    def test_argv_jsonl_silent(self) -> None:
        argv = NucleiWrapper().build_argv("http://10.5.0.10", ToolProfile())
        assert "-jsonl" in argv and "-silent" in argv
        assert argv[argv.index("-u") + 1] == "http://10.5.0.10"

    def test_parse_jsonl_lines(self) -> None:
        raw = (
            b'{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal",'
            b'"severity":"critical"},"matched-at":"http://10.5.0.10/","type":"http"}\n'
            b'{"template-id":"tech-detect","info":{"name":"Apache","severity":"info"},'
            b'"matched-at":"http://10.5.0.10/"}\n'
        )
        parsed = NucleiWrapper().parse("http://10.5.0.10", _res(raw))
        assert len(parsed["results"]) == 2
        assert parsed["results"][0]["severity"] == "critical"

    def test_parse_skips_bad_lines(self) -> None:
        parsed = NucleiWrapper().parse("x", _res(b'not json\n{"template-id":"t","info":{}}\n'))
        assert len(parsed["results"]) == 1


class TestNikto:
    def test_parse_vulnerabilities(self) -> None:
        raw = b'{"vulnerabilities":[{"id":"999990","msg":"server leaks inodes","url":"/","method":"GET"}]}'
        parsed = NiktoWrapper().parse("10.5.0.11", _res(raw))
        assert parsed["results"][0]["message"] == "server leaks inodes"


class TestWpscan:
    def test_parse_core_and_plugin_vulns(self) -> None:
        raw = (
            b'{"version":{"number":"5.0","vulnerabilities":[{"title":"core RCE"}]},'
            b'"plugins":{"contact-form":{"vulnerabilities":[{"title":"CF7 XSS"}]}}}'
        )
        parsed = WpscanWrapper().parse("10.5.0.11", _res(raw))
        assert parsed["version"] == "5.0"
        titles = {v["title"] for v in parsed["vulnerabilities"]}
        assert titles == {"core RCE", "CF7 XSS"}


class TestSqlmapConfirmOnly:
    def test_technique_is_boolean_only_and_no_extraction(self) -> None:
        argv = SqlmapConfirmWrapper().build_argv(
            "10.5.0.10",
            ToolProfile(args={"scheme": "http", "port": 3000, "path": "/s", "param": "q"}),
        )
        assert "--technique=B" in argv
        assert "-p" in argv and argv[argv.index("-p") + 1] == "q"
        # No extraction flags may ever appear.
        assert not any(a.startswith("--dump") or a in {"--dbs", "--tables"} for a in argv)

    def test_extraction_flag_is_refused(self) -> None:
        with pytest.raises(ValueError, match="forbidden"):
            SqlmapConfirmWrapper().build_argv(
                "10.5.0.10",
                ToolProfile(args={"port": 3000, "path": "/s", "extra_args": ["--dump"]}),
            )

    def test_parse_detects_injectable(self) -> None:
        out = b"Parameter: q (GET)\n    Type: boolean-based blind\n    Payload: q=1 AND 1=1\n"
        parsed = SqlmapConfirmWrapper().parse("10.5.0.10", _res(out))
        assert parsed["injectable"] is True
        assert parsed["parameter"] == "q"

    def test_parse_reports_not_injectable(self) -> None:
        parsed = SqlmapConfirmWrapper().parse("10.5.0.10", _res(b"all tested parameters do not appear to be injectable"))
        assert parsed["injectable"] is False
