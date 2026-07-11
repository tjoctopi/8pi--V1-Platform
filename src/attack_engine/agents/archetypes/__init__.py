"""Agent archetypes — one class per reasoning role (spec §4, rule #3)."""

from __future__ import annotations

from .converter import Converter
from .exploit import ExploitConfirmer
from .recon import SurfaceMapper
from .web import WebInquisitor

__all__ = ["SurfaceMapper", "WebInquisitor", "ExploitConfirmer", "Converter"]
