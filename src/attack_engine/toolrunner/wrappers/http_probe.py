"""HTTP probe wrapper — a single, measured request (read-only).

Verification oracles and exploit-confirmation modules send crafted requests and
measure the response. Crucially, they do this *through the Tool Runner* like any
other tool, so every probe is scope-checked, rate-limited, and audited — a
module can never reach a target the engagement doesn't allow (rule #2).

It drives ``curl`` and captures status / size / time. For confirmation without
disclosure it supports a ``match`` marker: the wrapper reports only whether the
marker appeared in the body (``matched: true/false``) — it never returns body
content to the agent (the full response still lands in the immutable audit as
evidence, like any raw tool output).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlencode

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

_SENTINEL = "__AEPROBE__"
# curl write-out, emitted after the body behind a sentinel so we can separate them.
_WRITE_OUT = f"\\n{_SENTINEL}HTTP:%{{http_code}} SIZE:%{{size_download}} TIME:%{{time_total}}"
_PARSE_RE = re.compile(rb"HTTP:(\d+)\s+SIZE:(\d+)\s+TIME:([\d.]+)")
_ALLOWED_METHODS = {"GET", "POST", "HEAD", "PUT", "OPTIONS"}


class HttpProbeWrapper(ToolWrapper):
    """A single HTTP request returning ``{status, size, time, matched}``.

    Profile args: ``scheme``, ``port``, ``path``, ``params`` (query, URL-encoded),
    ``method`` (default GET), ``data`` (form body for POST/PUT), ``basic_auth``
    (``"user:pass"`` — for default-credential checks), and ``match`` (a marker
    string; the wrapper returns only whether it appeared, never the body).
    """

    name = "http_probe"
    default_image = "curlimages/curl:8.8.0"
    default_timeout_sec = 30
    #: Bound the captured body so a probe is confirmation, not bulk retrieval.
    max_body_bytes = 65536

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        scheme = str(profile.args.get("scheme", "http"))
        port = profile.args.get("port")
        path = str(profile.args.get("path", "/"))
        if not path.startswith("/"):
            path = "/" + path
        params = profile.args.get("params") or {}
        query = f"?{urlencode(params)}" if params else ""
        hostport = f"{target}:{port}" if port else target
        url = f"{scheme}://{hostport}{path}{query}"

        method = str(profile.args.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported HTTP method {method!r}")

        # A caller (e.g. API-spec ingestion) may raise the body cap deliberately;
        # default keeps a probe "confirmation, not bulk retrieval".
        max_bytes = profile.args.get("max_bytes")
        cap = int(max_bytes) if isinstance(max_bytes, int) else self.max_body_bytes
        argv = [
            "curl", "-s", "-k",
            "-X", method,
            "-w", _WRITE_OUT,
            "--max-time", str(self.timeout_for(profile)),
            "--max-filesize", str(cap),
        ]
        # Include response headers in the captured output (e.g. so an oracle can
        # confirm an open redirect from the Location header). Redirects are NOT
        # followed — we observe the immediate response only.
        if profile.args.get("include_headers"):
            argv.append("-i")
        data = profile.args.get("data")
        if isinstance(data, dict) and data:
            for key, val in data.items():
                argv += ["--data-urlencode", f"{key}={val}"]
        elif isinstance(data, str) and data:
            argv += ["--data-urlencode", data]
        basic_auth = profile.args.get("basic_auth")
        if isinstance(basic_auth, str) and basic_auth:
            argv += ["-u", basic_auth]
        argv.append(url)
        return argv

    def is_mutating(self, profile: ToolProfile) -> bool:
        # A read/confirm probe. A caller that sets a mutating verb (PUT) can flag
        # it explicitly via the profile; by default this is treated read-only.
        return bool(profile.mutating)

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "tool": self.name, "target": target,
            "status": None, "size": None, "time": None, "body_sha256": None,
        }
        body, _, _tail = result.stdout.partition(_SENTINEL.encode())
        m = _PARSE_RE.search(result.stdout)
        if m is None:
            parsed["parse_error"] = True
            return parsed
        parsed["status"] = int(m.group(1))
        parsed["size"] = int(m.group(2))
        parsed["time"] = float(m.group(3))
        # Minimal disclosure: expose only a digest of the body, never its text.
        parsed["body_sha256"] = hashlib.sha256(body).hexdigest()
        return parsed

    @staticmethod
    def body_contains(raw: bytes, marker: str) -> bool:
        """Whether ``marker`` appears in the response body of a probe result.

        Modules (deterministic code) use this to confirm a reflected marker
        without the body ever being surfaced to an agent/LLM.
        """

        body, _, _ = raw.partition(_SENTINEL.encode())
        return marker.encode() in body

    @staticmethod
    def body_of(raw: bytes) -> bytes:
        """The response body bytes (everything before the write-out sentinel).

        For deterministic consumers only (e.g. parsing an OpenAPI/Swagger spec or
        robots.txt) — never surfaced to an LLM/agent as text.
        """

        body, _, _ = raw.partition(_SENTINEL.encode())
        return body
