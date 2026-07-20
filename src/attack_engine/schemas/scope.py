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
from datetime import datetime, timedelta
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

from .common import StrictModel, new_id, utcnow

# A conservative hostname pattern (RFC 1123 label rules, no wildcard here —
# wildcards are expressed as a separate allowlist entry kind).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

#: The sentinel signature a *test* authorization carries. It makes ``is_signed()``
#: true so the engine runs in dev/test with one call — but it is a recognizable
#: marker the engine REFUSES in production (see ``Engine.engagement``), so a
#: one-click test scope can never double as a real signed authorization.
TEST_AUTHORIZATION_SIGNATURE = "TEST-AUTH-NOT-FOR-PROD"

#: Action names a test scope pre-authorizes to run autonomously (tier ≥ 1). Note
#: this never overrides the always-gate lists: ``high_impact_actions`` and the
#: defense-evasion TTPs still gate even under a test authorization.
_DEFAULT_TEST_TECHNIQUES = frozenset({
    "establish_foothold", "lateral_move", "post_exploitation", "exploit_confirm",
})


def _classify_target(target: str) -> tuple[str, str] | None:
    """Classify a user target as ``("cidr", value)`` or ``("host", value)``.

    Accepts IPs, CIDRs (mask preserved), hostnames, and URLs (scheme/path/port
    stripped). Returns ``None`` for an empty/unusable target.
    """

    tok = target.strip()
    if not tok:
        return None
    if "://" in tok:  # a URL → reduce to its host[:port]/path
        parsed = urlparse(tok)
        tok = parsed.netloc or parsed.path
    # Try as an IP/CIDR first, with the mask intact (e.g. 192.168.0.0/24).
    try:
        return ("cidr", str(ipaddress.ip_network(tok, strict=False)))
    except ValueError:
        pass
    host = tok.split("/")[0].split(":")[0].strip()  # drop any path/port
    if not host:
        return None
    try:  # a bare IP with a port/path stripped
        return ("cidr", str(ipaddress.ip_network(host, strict=False)))
    except ValueError:
        return ("host", host)


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
    #: Tool allowlist. **Empty ⇒ no restriction** (any non-forbidden tool may
    #: run — preserves the historical default). When non-empty it is an explicit
    #: allowlist: only these tools may run, and the ``forbidden_tools`` denylist
    #: still wins over it. This is what the console's RoE "Allowed Tools" picker
    #: binds to, enforced at the Tool Runner boundary (rule #2).
    allowed_tools: frozenset[str] = Field(default_factory=frozenset)
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
    #: Explicitly excluded targets (CIDRs / hostnames). The denylist **wins** over
    #: the allowlist: a target inside an allowed range but also matching a denied
    #: entry is refused. This is the console RoE "Scope Denylist" — e.g. carve a
    #: fragile prod host out of an authorized subnet.
    denied_cidrs: tuple[str, ...] = Field(default_factory=tuple)
    denied_hosts: tuple[str, ...] = Field(default_factory=tuple)
    roe: RulesOfEngagement = Field(default_factory=RulesOfEngagement)

    # Authorisation binding.
    authorized_by: str | None = None
    signature: str | None = None
    #: Start of the authorized window (RoE "Window Start"). Before this instant
    #: the scope is not yet active and every tool call is refused (fail-safe).
    starts_at: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("allowed_cidrs", "denied_cidrs")
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

    @field_validator("allowed_hosts", "denied_hosts")
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

    @property
    def is_test_authorization(self) -> bool:
        """True when this scope carries the one-click *test* signature. The engine
        refuses such a scope in production — it is a dev/test convenience only."""

        return self.signature == TEST_AUTHORIZATION_SIGNATURE

    @classmethod
    def for_testing(
        cls,
        targets: list[str],
        *,
        engagement_id: str | None = None,
        autonomy_tier: int = 2,
        authorized_techniques: frozenset[str] | None = None,
        read_only: bool = False,
        ttl_hours: int = 8,
    ) -> Scope:
        """One-click **test** authorization — a ready-to-run signed scope.

        Convenience for local/range testing so you don't hand-craft a Scope: give
        it targets (IPs, CIDRs, hostnames, or URLs) and it returns a scope that is
        signed (with the :data:`TEST_AUTHORIZATION_SIGNATURE` sentinel), autonomous
        at ``autonomy_tier``, and pre-authorizes the common offensive actions — so
        the engine acts without per-step friction.

        This is **not** real authorization: the sentinel makes the engine refuse
        the scope in production (fail-safe), and it auto-expires after ``ttl_hours``.
        The always-gate lists (``high_impact_actions`` + defense-evasion TTPs) still
        gate. For a real engagement, build a properly signed Scope instead.
        """

        cidrs: list[str] = []
        hosts: list[str] = []
        for target in targets:
            classified = _classify_target(target)
            if classified is None:
                continue
            (cidrs if classified[0] == "cidr" else hosts).append(classified[1])
        if not cidrs and not hosts:
            raise ValueError("for_testing requires at least one target")

        return cls(
            engagement_id=engagement_id or new_id("engagement-test"),
            allowed_cidrs=tuple(cidrs),
            allowed_hosts=tuple(hosts),
            roe=RulesOfEngagement(
                read_only=read_only,
                autonomy_tier=autonomy_tier,
                authorized_techniques=(
                    authorized_techniques
                    if authorized_techniques is not None
                    else _DEFAULT_TEST_TECHNIQUES
                ),
                # Verification oracles fire rapid, bounded probes (e.g. an
                # injection screen issues many http_probes in a burst). The 5/s
                # default throttles them so screening "halts by governance"
                # mid-run — a false stop for a test authorization the operator
                # explicitly opted into. Give it headroom so the autonomous
                # pipeline runs to completion; scope/RoE enforcement is unchanged.
                default_rate_limit=RateLimit(requests_per_sec=50, burst=20),
            ),
            authorized_by="test-operator",
            signature=TEST_AUTHORIZATION_SIGNATURE,
            expires_at=utcnow() + timedelta(hours=ttl_hours),
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or utcnow()) >= self.expires_at

    def is_not_yet_active(self, now: datetime | None = None) -> bool:
        """True before the authorized window opens (``starts_at`` in the future)."""

        if self.starts_at is None:
            return False
        return (now or utcnow()) < self.starts_at
