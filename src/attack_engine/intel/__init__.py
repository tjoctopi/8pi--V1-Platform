"""Attack-surface intelligence — the offensive layer's input.

Turns the blackboard's raw findings into a structured, offensive-oriented
*dossier* per asset: services + versions, technology, endpoints + parameters,
concrete attack leads (injection points / CVEs / default-cred / XSS), exposed
items, and observations by severity. This is what an operator (or the automated
offensive layer) reads to plan and execute — reconnaissance made actionable.
"""

from __future__ import annotations

from .surface import (
    AssetIntel,
    AttackLead,
    AttackSurface,
    EndpointIntel,
    ExposedItem,
    ServiceIntel,
    build_attack_surface,
)

__all__ = [
    "AssetIntel",
    "AttackLead",
    "AttackSurface",
    "EndpointIntel",
    "ExposedItem",
    "ServiceIntel",
    "build_attack_surface",
]
