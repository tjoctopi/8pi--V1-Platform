"""Fixtures for Tool Runner tests: a programmable fake sandbox + tool fixtures."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec

# --- Realistic tool output fixtures ------------------------------------------

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.4.12">
 <host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.12" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
     <state state="closed"/>
     <service name="ssh"/>
   </port>
   <port protocol="tcp" portid="80">
     <state state="open"/>
     <service name="http" product="Apache httpd" version="2.4.49"/>
   </port>
   <port protocol="tcp" portid="3306">
     <state state="open"/>
     <service name="mysql" product="MySQL" version="5.5.61"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""

FFUF_JSON = b"""{
  "results": [
    {"input": {"FUZZ": "admin"}, "url": "http://10.0.4.12/admin", "status": 200, "length": 1234, "words": 56},
    {"input": {"FUZZ": "login"}, "url": "http://10.0.4.12/login", "status": 301, "length": 0, "words": 1}
  ]
}
"""


def logical_tool(argv: list[str]) -> str:
    """Map a real sandbox argv back to its logical tool name.

    Production wrappers build truthful argvs for each image's actual executable,
    which may not equal the tool's registry name:

    * shell-wrapped tools — ``sh -c "ffuf ...; cat out.json"`` (ffuf captures
      clean JSON via a tmpfile) → the tool is the script's first token;
    * path/suffix'd binaries — ``/app/dalfox`` (dalfox), ``nikto.pl`` (nikto).

    Tests reason in logical names, so both fake sandboxes normalise through
    this single helper.
    """

    if not argv:
        return ""
    head = argv[0]
    if head in ("sh", "/bin/sh", "bash") and len(argv) >= 3:
        tokens = argv[-1].split()
        head = tokens[0] if tokens else ""
    base = head.rsplit("/", 1)[-1]
    for suffix in (".pl", ".py"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


class FakeSandbox(Sandbox):
    """A sandbox that returns pre-programmed output keyed by tool binary.

    Records every spec it was asked to run so tests can assert on the argv the
    wrapper built without ever executing a real process.
    """

    name = "fake"

    def __init__(self, responses: dict[str, SandboxResult] | None = None) -> None:
        self._responses = responses or {}
        self.calls: list[SandboxSpec] = []

    def set_response(self, binary: str, result: SandboxResult) -> None:
        self._responses[binary] = result

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        binary = logical_tool(spec.argv)
        return self._responses.get(
            binary,
            SandboxResult(0, b"", b"", 0.01, self.name),
        )


def _result(stdout: bytes, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, stdout, b"", 0.05, "fake")


@pytest.fixture
def fake_sandbox() -> FakeSandbox:
    sb = FakeSandbox()
    sb.set_response("nmap", _result(NMAP_XML))
    sb.set_response("ffuf", _result(FFUF_JSON))
    return sb


@pytest.fixture
def result_factory() -> Callable[..., SandboxResult]:
    return _result
