"""Verification oracles — one deterministic confirmer per finding class."""

from __future__ import annotations

from .base import Oracle, OracleRegistry, OracleResult
from .open_redirect import OpenRedirectOracle
from .reflected_xss import ReflectedXssOracle
from .sqli_boolean_blind import SqliBooleanBlindOracle
from .version_regrab import VersionRegrabOracle

__all__ = [
    "Oracle",
    "OracleRegistry",
    "OracleResult",
    "VersionRegrabOracle",
    "SqliBooleanBlindOracle",
    "ReflectedXssOracle",
    "OpenRedirectOracle",
    "default_oracle_registry",
]


def default_oracle_registry() -> OracleRegistry:
    """The read-only confirmation oracle set.

    Each confirms a vulnerability class by observing only metadata or our own
    injected marker — never target data — so confirmation is safe and ungated;
    weaponisation of any confirmed lead remains behind the human gate.
    """

    reg = OracleRegistry()
    reg.register(VersionRegrabOracle())
    reg.register(SqliBooleanBlindOracle())
    reg.register(ReflectedXssOracle())
    reg.register(OpenRedirectOracle())
    return reg
