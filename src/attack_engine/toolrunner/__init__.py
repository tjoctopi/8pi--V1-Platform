"""Tool Runner — the typed, scope-enforced execution boundary (spec §3, §6.2).

Every security tool runs through :class:`ToolRunner.run`. Agents call
``runner.run("nmap", target, profile)`` — they *never* shell out freely. The
boundary enforces, in order: scope (radix-trie CIDR), RoE, rate limit, sandbox
isolation, then immutable audit. This is rule #2 made concrete.
"""

from __future__ import annotations

from .ratelimit import RateLimiter
from .registry import ToolRegistry, default_registry
from .runner import ToolRunner
from .sandbox import (
    DockerSandbox,
    LocalSandbox,
    NoopSandbox,
    Sandbox,
    SandboxResult,
    SandboxSpec,
    build_sandbox,
)
from .scope import ScopeEnforcer

__all__ = [
    "DockerSandbox",
    "LocalSandbox",
    "NoopSandbox",
    "RateLimiter",
    "Sandbox",
    "SandboxResult",
    "SandboxSpec",
    "ScopeEnforcer",
    "ToolRegistry",
    "ToolRunner",
    "build_sandbox",
    "default_registry",
]
