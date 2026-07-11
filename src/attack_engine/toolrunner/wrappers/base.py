"""Tool wrapper contract (spec §6.2).

A wrapper is the *only* thing that knows how to turn a validated
:class:`~attack_engine.schemas.tools.ToolProfile` into a safe argv and how to
parse that tool's raw output into structured data. Agents reference wrappers by
name through the registry and pass profiles — they never construct a command
line, so there is no shell injection surface (rule #2, roles-not-tool-copies
rule #3).

Adding "another way of attacking" = writing one wrapper and registering it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ...schemas.tools import ToolProfile
from ..sandbox import SandboxResult


class ToolWrapper(ABC):
    """Base class for every tool integration."""

    #: Registry name agents use, e.g. ``"nmap"``.
    name: str
    #: Container image (used by the Docker sandbox).
    default_image: str = ""
    #: Default per-invocation timeout if the profile doesn't set one.
    default_timeout_sec: int = 300
    #: A commercial/licensed tool (Nessus, Burp Enterprise). The Tool Runner
    #: refuses it unless the engagement RoE explicitly enables it — representing
    #: completed procurement / legal / headless-terms sign-off (spec §7, §9).
    licensed: bool = False

    @abstractmethod
    def build_argv(self, target: str, profile: ToolProfile) -> list[str]:
        """Return the argv list to execute. Never a shell string."""

    @abstractmethod
    def parse(self, target: str, result: SandboxResult) -> dict[str, Any]:
        """Turn raw sandbox output into structured, tool-shaped data."""

    def is_mutating(self, profile: ToolProfile) -> bool:
        """Whether this profile changes target state (blocked under read-only).

        Defaults to the profile's own flag; wrappers override when a preset is
        inherently mutating regardless of what the caller declared.
        """

        return profile.mutating

    def mounts(self, profile: ToolProfile) -> list[tuple[str, str]]:
        """Read-only mounts (source, container_path) this tool needs.

        E.g. a wordlist for ffuf or a template set for Nuclei. Sources are host
        paths or docker volume names; the sandbox mounts them ``:ro``. Default
        is none.
        """

        return []

    def timeout_for(self, profile: ToolProfile) -> int:
        return profile.timeout_sec or self.default_timeout_sec
