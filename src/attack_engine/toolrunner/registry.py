"""Tool Registry — name → wrapper resolution (spec §8, rule #3).

Breadth ("every way of attacking") is achieved by *registering* wrappers, not
by cloning agents. An agent spec lists tool names; the registry resolves each to
a wrapper instance at runtime. This is the seam that lets the engine scale to
any number of tools without new agent code.
"""

from __future__ import annotations

from ..errors import ToolNotRegisteredError
from .wrappers.base import ToolWrapper
from .wrappers.ffuf import FfufWrapper
from .wrappers.http_probe import HttpProbeWrapper
from .wrappers.nmap import NmapWrapper


class ToolRegistry:
    """A mutable map of tool name → :class:`ToolWrapper` instance."""

    def __init__(self) -> None:
        self._wrappers: dict[str, ToolWrapper] = {}

    def register(self, wrapper: ToolWrapper, *, replace: bool = False) -> None:
        if not getattr(wrapper, "name", ""):
            raise ValueError("wrapper must define a non-empty 'name'")
        if wrapper.name in self._wrappers and not replace:
            raise ValueError(f"tool {wrapper.name!r} already registered")
        self._wrappers[wrapper.name] = wrapper

    def resolve(self, name: str) -> ToolWrapper:
        try:
            return self._wrappers[name]
        except KeyError:
            raise ToolNotRegisteredError(name) from None

    def is_registered(self, name: str) -> bool:
        return name in self._wrappers

    def names(self) -> list[str]:
        return sorted(self._wrappers)

    def __len__(self) -> int:
        return len(self._wrappers)


def default_registry() -> ToolRegistry:
    """The current tool registry.

    Sprint 0: Nmap + ffuf (recon). Sprint 1 adds the scope-enforced HTTP probe
    (verification), the web tools (Nuclei/Nikto/WPScan), and the confirm-only
    SQLMap wrapper.
    """

    from .wrappers.dalfox import DalfoxWrapper
    from .wrappers.discovery import AmassWrapper, SearchsploitWrapper, SubfinderWrapper
    from .wrappers.httpx import HttpxWrapper
    from .wrappers.katana import KatanaWrapper
    from .wrappers.licensed import BurpEnterpriseWrapper, NessusWrapper
    from .wrappers.masscan import MasscanWrapper
    from .wrappers.metasploit import MetasploitCheckWrapper
    from .wrappers.nikto import NiktoWrapper
    from .wrappers.nuclei import NucleiWrapper
    from .wrappers.sqlmap import SqlmapConfirmWrapper
    from .wrappers.wpscan import WpscanWrapper

    reg = ToolRegistry()
    # Recon (read-only).
    reg.register(NmapWrapper())
    reg.register(MasscanWrapper())
    reg.register(FfufWrapper())
    reg.register(HttpxWrapper())
    reg.register(HttpProbeWrapper())
    reg.register(SubfinderWrapper())
    reg.register(AmassWrapper())
    reg.register(SearchsploitWrapper())
    # Web (read-only probes).
    reg.register(NucleiWrapper())
    reg.register(NiktoWrapper())
    reg.register(WpscanWrapper())
    reg.register(KatanaWrapper())
    reg.register(DalfoxWrapper())
    # Exploit confirmation (gated; SQLMap read-only-confirm, Metasploit check-only+mutating).
    reg.register(SqlmapConfirmWrapper())
    reg.register(MetasploitCheckWrapper())
    # Licensed/commercial — registered but refused unless RoE enables them.
    reg.register(NessusWrapper())
    reg.register(BurpEnterpriseWrapper())
    return reg
