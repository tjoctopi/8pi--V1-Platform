"""Tool wrappers — one per integration (spec §8 toolrunner/wrappers/)."""

from __future__ import annotations

from .base import ToolWrapper
from .dalfox import DalfoxWrapper
from .ffuf import FfufWrapper
from .http_probe import HttpProbeWrapper
from .httpx import HttpxWrapper
from .katana import KatanaWrapper
from .licensed import BurpEnterpriseWrapper, NessusWrapper
from .masscan import MasscanWrapper
from .metasploit import MetasploitCheckWrapper
from .nikto import NiktoWrapper
from .nmap import NmapWrapper
from .nuclei import NucleiWrapper
from .sqlmap import SqlmapConfirmWrapper
from .wpscan import WpscanWrapper

__all__ = [
    "ToolWrapper",
    "NmapWrapper",
    "MasscanWrapper",
    "FfufWrapper",
    "HttpxWrapper",
    "HttpProbeWrapper",
    "NucleiWrapper",
    "NiktoWrapper",
    "WpscanWrapper",
    "KatanaWrapper",
    "DalfoxWrapper",
    "SqlmapConfirmWrapper",
    "MetasploitCheckWrapper",
    "NessusWrapper",
    "BurpEnterpriseWrapper",
]
