"""Scope & Rules-of-Engagement (RoE) schemas.

A :class:`Scope` is the machine-readable contract for an engagement: which
targets are in bounds, how fast we may hit them, and what is forbidden. It is
signed at the boundary (the Tool Runner) — *never* interpreted by an agent.

The runtime enforcement (radix-trie CIDR matching, rate limiting) lives in
``attack_engine.toolrunner.scope``; this module is purely the data contract so
schemas stay dependency-free and trivially serialisable into the audit log.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .common import StrictModel, utcnow

# A conservative hostname pattern (RFC 1123 label rules, no wildcard here —
# wildcards are expressed as a separate allowlist entry kind).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class RateLimit(StrictModel):
    """Per-(tool, target) request ceiling, enforced in the Tool Runner."""

    requests_per_sec: float = Field(gt=0, le=1000)
    burst: int = Field(default=1, ge=1, le=1000)

    @model_validator(mode="after")
    def _burst_ge_one(self) -> RateLimit:
        # burst must be at least 1 to admit a single request.
        if self.burst < 1:
            raise ValueError("burst must be >= 1")
        return self


class RulesOfEngagement(StrictModel):
    """The human-signed rules governing what the engine may do.

    ``read_only`` is the master safety switch: when true the Tool Runner
    refuses to launch any tool profile flagged as mutating, regardless of
    per-agent guardrails.
    """

    read_only: bool = True
    #: Tool names explicitly forbidden for this engagement (denylist wins).
    forbidden_tools: frozenset[str] = Field(default_factory=frozenset)
    #: Actions that always require a human gate before executing.
    gated_actions: frozenset[str] = Field(
        default_factory=lambda: frozenset({"exploit_confirm", "apply_fix", "containment"})
    )
    #: Default rate limit applied when a target has no more specific one.
    default_rate_limit: RateLimit = Field(default_factory=lambda: RateLimit(requests_per_sec=5))
    #: Hard cap on total tool invocations for the engagement (0 = unlimited).
    max_total_tool_calls: int = Field(default=0, ge=0)
    #: Licensed tools (Nessus, Burp Enterprise) enabled for this engagement —
    #: an explicit signal that procurement/legal/headless-terms are signed off.
    #: Empty ⇒ no licensed tool may run (the safe default).
    licensed_tools_enabled: frozenset[str] = Field(default_factory=frozenset)

    # --- engagement-boundary authorization (autonomy) -----------------------
    #: How autonomously agents may act *within* the authorized scope:
    #:   0 — gate every controlled action (default; a scanner that asks each time)
    #:   1 — autonomous in an owned range (approve the run, then hands off)
    #:   2 — autonomous in an authorized customer scope
    #:   3 — continuous / always-on
    #: Tiers >0 pre-authorize aggression at the ENGAGEMENT boundary instead of
    #: per action — the shift that turns a scanner into an adversary. They take
    #: effect only when the scope is signed and unexpired; otherwise the engine
    #: falls back to gating (fail-safe).
    autonomy_tier: int = Field(default=0, ge=0, le=3)
    #: Actions/techniques (action names or MITRE ATT&CK ids) the signed RoE
    #: pre-authorizes to run autonomously at tier ≥ 1. Anything not listed still
    #: gates — authorization is an explicit allowlist, never implicit.
    authorized_techniques: frozenset[str] = Field(default_factory=frozenset)
    #: Actions that ALWAYS require a human gate, even at tier ≥ 1 — the short,
    #: explicit high-impact list: destructive, production-data-touching, or
    #: real-world-effect actions. These can never be pre-authorized away.
    high_impact_actions: frozenset[str] = Field(
        default_factory=lambda: frozenset({
            "apply_fix", "containment", "data_destruction", "dos",
            "exfiltration", "prod_data_access",
        })
    )


class Scope(StrictModel):
    """The complete, signed scope of one engagement.

    Allowlists hold CIDR networks and hostnames. Everything not explicitly
    allowed is denied. The signature binds the scope to a human authorisation;
    the Tool Runner refuses to operate on an unsigned scope in prod.
    """

    engagement_id: str = Field(pattern=r"^eng(agement)?-[A-Za-z0-9_-]+$")
    allowed_cidrs: tuple[str, ...] = Field(default_factory=tuple)
    allowed_hosts: tuple[str, ...] = Field(default_factory=tuple)
    roe: RulesOfEngagement = Field(default_factory=RulesOfEngagement)

    # Authorisation binding.
    authorized_by: str | None = None
    signature: str | None = None
    expires_at: datetime | None = None

    @field_validator("allowed_cidrs")
    @classmethod
    def _validate_cidrs(cls, cidrs: tuple[str, ...]) -> tuple[str, ...]:
        normalised: list[str] = []
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {c!r}: {exc}") from exc
            normalised.append(str(net))
        return tuple(normalised)

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_hosts(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        for h in hosts:
            if not _HOSTNAME_RE.match(h):
                raise ValueError(f"invalid hostname {h!r}")
        return tuple(h.lower() for h in hosts)

    @model_validator(mode="after")
    def _non_empty(self) -> Scope:
        if not self.allowed_cidrs and not self.allowed_hosts:
            raise ValueError("scope must allow at least one CIDR or host")
        return self

    def is_signed(self) -> bool:
        return bool(self.signature) and bool(self.authorized_by)

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or utcnow()) >= self.expires_at
