"""ffuf wrapper — web content/endpoint discovery (read-only).

We run ffuf in silent mode emitting JSON to stdout and parse that structured
output. Fuzzing endpoints is a GET-based discovery activity — read-only — so no
preset here mutates target state. The ``FUZZ`` keyword and wordlist come from
the profile args; the wrapper controls the rest of the argv.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper

#: A curated common-paths wordlist shipped with the engine, mounted read-only
#: into the ffuf container (so no external SecLists dependency is required).
_BUNDLED_WORDLIST = (
    Path(__file__).resolve().parent.parent / "data" / "wordlists" / "common.txt"
)
_CONTAINER_WORDLIST = "/wordlists/common.txt"


class FfufWrapper(ToolWrapper):
    name = "ffuf"
    default_image = "secsi/ffuf:latest"
    default_timeout_sec = 600

    @staticmethod
    def _build_url(target: str, profile: ToolProfile) -> str:
        """Construct the fuzz URL.

        The Tool Runner validates a *bare host/IP* against scope, so agents pass
        one (e.g. ``10.0.4.12``) plus optional scheme/port/path in the profile.
        A full URL target (dev convenience) is used verbatim. The ``FUZZ``
        keyword is appended if the caller didn't place it.
        """

        if "://" in target:
            base = target
        else:
            scheme = str(profile.args.get("scheme", "http"))
            port = profile.args.get("port")
            hostport = f"{target}:{port}" if port else target
            base = f"{scheme}://{hostport}"
        if "FUZZ" not in base:
            base = base.rstrip("/") + "/FUZZ"
        return base

    #: Where ffuf writes its JSON report inside the container (tmpfs, writable).
    _OUT_FILE = "/tmp/ffuf-out.json"

    def _ffuf_args(self, target: str, profile: ToolProfile) -> list[str]:
        url = self._build_url(target, profile)
        wordlist = str(profile.args.get("wordlist") or _CONTAINER_WORDLIST)
        args = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-of", "json",
            "-o", self._OUT_FILE,
            "-ac",  # auto-calibrate: learn+filter the catch-all (SPA) response
            "-s",   # silent: no interactive/progress noise
        ]
        mc = profile.args.get("match_codes")
        if isinstance(mc, str) and mc:
            args += ["-mc", mc]
        fc = profile.args.get("filter_codes")
        if isinstance(fc, str) and fc:
            args += ["-fc", fc]
        return args

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        """Run ffuf writing JSON to a tmpfs file, then emit *only* that file.

        ffuf interleaves live results with the JSON report if ``-o`` is stdout,
        so we write the report to a file and ``cat`` it — guaranteeing clean,
        parseable JSON on stdout. The argv is fully wrapper-controlled; the only
        interpolated value (the URL) is shell-quoted, and the target host has
        already passed scope validation before we get here.
        """

        ffuf = " ".join(shlex.quote(a) for a in self._ffuf_args(target, profile))
        script = f"{ffuf} >/dev/null 2>&1; cat {shlex.quote(self._OUT_FILE)}"
        return ["sh", "-c", script]

    def mounts(self, profile: ToolProfile) -> list[tuple[str, str]]:
        # Mount the bundled wordlist unless the caller supplies its own path.
        if profile.args.get("wordlist"):
            return []
        return [(str(_BUNDLED_WORDLIST), _CONTAINER_WORDLIST)]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {"tool": self.name, "target": target, "results": []}
        raw = result.stdout.strip()
        if not raw:
            return parsed
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            parsed["parse_error"] = True
            return parsed
        for item in doc.get("results", []) or []:
            parsed["results"].append(
                {
                    "path": (item.get("input") or {}).get("FUZZ"),
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words"),
                }
            )
        return parsed
