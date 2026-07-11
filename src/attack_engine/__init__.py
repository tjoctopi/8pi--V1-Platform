"""8π Coordinated Attack Engine.

A coordinated, accuracy-first purple-team automation platform built on the
propose/verify discipline: the model *proposes*, deterministic code *verifies*.

The four non-negotiable rules (enforced structurally, not by convention):

1. Propose vs. verify — only a passed verification oracle promotes a finding.
2. Scope at the boundary — the Tool Runner refuses out-of-scope targets.
3. Roles, not tool-copies — one archetype per role; tools come from a registry.
4. Model-agnostic (BYOM) — every model call routes through the gateway.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
