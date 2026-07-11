"""Wrapper argv-building and parsing tests (no execution)."""

from __future__ import annotations

from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.sandbox import SandboxResult
from attack_engine.toolrunner.wrappers.ffuf import FfufWrapper
from attack_engine.toolrunner.wrappers.nmap import NmapWrapper

from .conftest import FFUF_JSON, NMAP_XML


def _res(stdout: bytes) -> SandboxResult:
    return SandboxResult(0, stdout, b"", 0.01, "fake")


class TestNmap:
    def test_argv_default_preset(self) -> None:
        argv = NmapWrapper().build_argv("10.0.4.12", ToolProfile())
        assert argv[0] == "nmap"
        assert "-oX" in argv and "-" in argv
        assert argv[-1] == "10.0.4.12"
        assert "-sV" in argv

    def test_argv_explicit_ports_override_preset(self) -> None:
        argv = NmapWrapper().build_argv(
            "10.0.4.12", ToolProfile(preset="full", args={"ports": "80,443"})
        )
        assert "-p" in argv
        assert "80,443" in argv
        assert "-p-" not in argv  # preset's all-ports flag was stripped

    def test_no_shell_metachars_reach_argv(self) -> None:
        # ToolProfile validation rejects dangerous strings before build_argv.
        import pytest

        with pytest.raises(ValueError, match="metacharacter"):
            ToolProfile(args={"ports": "80; rm -rf /"})

    def test_nmap_is_never_mutating(self) -> None:
        assert NmapWrapper().is_mutating(ToolProfile(mutating=True)) is False

    def test_parse_open_ports_only(self) -> None:
        parsed = NmapWrapper().parse("10.0.4.12", _res(NMAP_XML))
        assert parsed["up"] is True
        ports = {p["port"] for p in parsed["ports"]}
        assert ports == {80, 3306}  # 22 was closed → excluded
        apache = next(p for p in parsed["ports"] if p["port"] == 80)
        assert apache["product"] == "Apache httpd"
        assert apache["version"] == "2.4.49"

    def test_parse_empty_output(self) -> None:
        parsed = NmapWrapper().parse("10.0.4.12", _res(b""))
        assert parsed["ports"] == []
        assert parsed["up"] is False

    def test_parse_malformed_xml_flagged(self) -> None:
        parsed = NmapWrapper().parse("10.0.4.12", _res(b"<not-xml"))
        assert parsed.get("parse_error") is True


class TestFfuf:
    def test_argv_appends_fuzz_keyword(self) -> None:
        args = FfufWrapper()._ffuf_args("http://10.0.4.12", ToolProfile())
        i = args.index("-u")
        assert args[i + 1].endswith("/FUZZ")

    def test_argv_respects_existing_fuzz(self) -> None:
        args = FfufWrapper()._ffuf_args(
            "http://10.0.4.12/api/FUZZ/v1", ToolProfile()
        )
        i = args.index("-u")
        assert args[i + 1] == "http://10.0.4.12/api/FUZZ/v1"

    def test_argv_json_output_to_file(self) -> None:
        args = FfufWrapper()._ffuf_args("http://10.0.4.12", ToolProfile())
        assert "-of" in args and "json" in args
        assert "-s" in args and "-ac" in args
        # Report is written to a file, not stdout, to avoid interleaved output.
        assert args[args.index("-o") + 1] == FfufWrapper._OUT_FILE

    def test_build_argv_wraps_in_shell_and_cats_report(self) -> None:
        # build_argv runs ffuf then emits *only* the JSON file to stdout.
        argv = FfufWrapper().build_argv("http://10.0.4.12", ToolProfile())
        assert argv[0] == "sh" and argv[1] == "-c"
        assert "ffuf" in argv[2]
        assert f"cat {FfufWrapper._OUT_FILE}" in argv[2]

    def test_match_and_filter_codes(self) -> None:
        args = FfufWrapper()._ffuf_args(
            "http://10.0.4.12",
            ToolProfile(args={"match_codes": "200,301", "filter_codes": "404"}),
        )
        assert args[args.index("-mc") + 1] == "200,301"
        assert args[args.index("-fc") + 1] == "404"

    def test_parse_results(self) -> None:
        parsed = FfufWrapper().parse("http://10.0.4.12", _res(FFUF_JSON))
        assert len(parsed["results"]) == 2
        paths = {r["path"] for r in parsed["results"]}
        assert paths == {"admin", "login"}
        admin = next(r for r in parsed["results"] if r["path"] == "admin")
        assert admin["status"] == 200

    def test_parse_malformed_json_flagged(self) -> None:
        parsed = FfufWrapper().parse("http://10.0.4.12", _res(b"{bad json"))
        assert parsed.get("parse_error") is True
