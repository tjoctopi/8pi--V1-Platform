"""Kubernetes recon wrapper — kube-hunter (read-only).

Adds a container-orchestration attack surface the fleet previously could not
see. The web/AD tools map HTTP apps and directory identities, but nothing
recognised an exposed Kubernetes control plane. ``kube-hunter --remote`` does
active discovery + reporting only (it probes well-known k8s ports — API server
:6443, kubelet :10250, etcd :2379 — and reports what it can reach); it does not
mutate cluster state, so it is read-only like nmap.

We drive it with ``--report json`` and parse the JSON deterministically into
``{nodes, services, vulnerabilities, is_kubernetes}``. The Recon observer turns
that into an exposure finding (the cluster is recognised) plus one finding per
concrete kube-hunter weakness.
"""

from __future__ import annotations

import json
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult
from .base import ToolWrapper


def _host(target: str) -> str:
    """``kube-hunter --remote`` wants a bare host/IP — strip scheme, path/CIDR, port.

    Recon targets can arrive as ``https://h:6443``, ``34.201.230.6/32`` or a bare
    host; normalise all of them to the host so the probe is well-formed.
    """

    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]  # drop any path or CIDR suffix
    if t.count(":") == 1:  # host:port (leave IPv6 literals alone)
        t = t.split(":", 1)[0]
    return t


class KubeHunterWrapper(ToolWrapper):
    name = "kube_hunter"
    default_image = "aquasec/kube-hunter:latest"
    default_timeout_sec = 300

    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        # kube-hunter defaults to 800 worker threads, which trips the sandbox
        # ``--pids-limit`` ("can't start new thread"). Cap the pool well under the
        # limit so it runs cleanly under the hardened sandbox.
        return [
            "kube-hunter",
            "--remote",
            _host(target),
            "--report",
            "json",
            "--log",
            "none",
            "--num-worker-threads",
            "30",
        ]

    def is_mutating(self, profile: ToolProfile) -> bool:
        return False  # remote discovery + reporting only; no cluster mutation

    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "tool": self.name,
            "host": _host(target),
            "is_kubernetes": False,
            "nodes": [],
            "services": [],
            "vulnerabilities": [],
        }
        raw = result.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return parsed

        # kube-hunter prints a single JSON object; parse defensively in case any
        # log line leaks onto stdout (try the whole buffer, then each line, then
        # from the first brace).
        doc: Any = None
        candidates = [raw, *reversed(raw.splitlines())]
        if "{" in raw:
            candidates.append(raw[raw.find("{") :])
        for chunk in candidates:
            chunk = chunk.strip()
            if not chunk.startswith("{"):
                continue
            try:
                doc = json.loads(chunk)
                break
            except (json.JSONDecodeError, ValueError):
                continue
        if not isinstance(doc, dict):
            parsed["parse_error"] = True
            return parsed

        parsed["nodes"] = doc.get("nodes") or []
        parsed["services"] = doc.get("services") or []
        parsed["vulnerabilities"] = doc.get("vulnerabilities") or []
        parsed["is_kubernetes"] = bool(parsed["nodes"] or parsed["services"])
        return parsed
