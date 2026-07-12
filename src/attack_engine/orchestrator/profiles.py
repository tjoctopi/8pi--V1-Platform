"""Adversary profiles — declarative "emulate this actor" playbooks.

A profile names the TTPs an actor uses (as action names / MITRE ATT&CK ids). It
is *not* an authorization: the signed RoE decides what actually runs autonomously
(see :mod:`attack_engine.governance.authorization`). Built-ins cover the common
starting shapes; custom profiles load from YAML.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .campaign import AdversaryProfile

#: Starter profiles. Techniques mix action names (exploit_confirm) and ATT&CK ids
#: so they line up with what the RoE ``authorized_techniques`` allowlist grants.
BUILTIN_PROFILES: dict[str, AdversaryProfile] = {
    "web-opportunist": AdversaryProfile(
        id="web-opportunist",
        name="Opportunistic Web Attacker",
        description="Exploits exposed web vulnerabilities (SQLi/XSS/redirect) for "
                    "initial access. The safe starting profile for range work.",
        kill_chain=("T1595", "T1595.002", "T1083", "T1190", "T1059.007"),
        techniques=frozenset({"exploit_confirm", "T1190", "T1059.007"}),
        autonomy_tier=1,
    ),
    "network-intruder": AdversaryProfile(
        id="network-intruder",
        name="Network Intruder",
        description="Initial access via service/CVE exploitation, then privilege "
                    "escalation and lateral movement toward a crown-jewel host.",
        kill_chain=("T1595", "T1046", "T1518", "T1190", "T1210",
                    "T1078", "T1068", "T1021"),
        techniques=frozenset({
            "exploit_confirm", "post_exploitation", "T1190", "T1210", "T1078",
            "privilege_escalation", "lateral_movement",
        }),
        autonomy_tier=2,
    ),
    "adversary-emulation": AdversaryProfile(
        id="adversary-emulation",
        name="Full Kill-Chain Adversary",
        description="End-to-end emulation: recon → initial access → execution → "
                    "credential access → privilege escalation → lateral movement "
                    "→ C2. Impact tactics stay human-gated.",
        kill_chain=("T1595", "T1046", "T1518", "T1190", "T1059", "T1552",
                    "T1078", "T1068", "T1210", "T1021", "T1071", "T1082"),
        techniques=frozenset({
            "exploit_confirm", "post_exploitation", "T1190", "T1059", "T1078",
            "T1210", "T1021", "T1071", "privilege_escalation", "lateral_movement",
        }),
        autonomy_tier=2,
    ),
}


def get_profile(profile_id: str) -> AdversaryProfile:
    """Return a built-in profile by id (raises ``KeyError`` if unknown)."""

    return BUILTIN_PROFILES[profile_id]


def load_profile(path: str | Path) -> AdversaryProfile:
    """Load a custom adversary profile from a YAML file."""

    data: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
    if "techniques" in data and isinstance(data["techniques"], list):
        data["techniques"] = frozenset(str(t) for t in data["techniques"])
    return AdversaryProfile.model_validate(data)
