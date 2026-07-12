"""MITRE ATT&CK model — tactics, techniques, and capability mapping.

Minimal, dependency-free representation of the slice of ATT&CK Enterprise the
engine operates in. A :class:`Technique` is a versioned reference entry; a
:class:`TechniqueCapability` records *how* the engine realizes it (which tool,
exploit module, oracle, or post-ex action) and whether that capability is
``available`` today or ``planned``. The :class:`TechniqueLibrary` ties them
together and answers coverage questions.
"""

from __future__ import annotations

from enum import Enum

from ..schemas.common import StrictModel


class Tactic(str, Enum):
    """ATT&CK Enterprise tactics (value = ATT&CK id)."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"

    @property
    def display(self) -> str:
        return self.name.replace("_", " ").title()


#: Canonical kill-chain ordering of the tactics (for reporting / campaign flow).
TACTIC_ORDER: tuple[Tactic, ...] = (
    Tactic.RECONNAISSANCE, Tactic.RESOURCE_DEVELOPMENT, Tactic.INITIAL_ACCESS,
    Tactic.EXECUTION, Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION,
    Tactic.DEFENSE_EVASION, Tactic.CREDENTIAL_ACCESS, Tactic.DISCOVERY,
    Tactic.LATERAL_MOVEMENT, Tactic.COLLECTION, Tactic.COMMAND_AND_CONTROL,
    Tactic.EXFILTRATION, Tactic.IMPACT,
)


class CapabilityKind(str, Enum):
    """What kind of engine component realizes a technique."""

    TOOL = "tool"                    # a registered Tool Runner wrapper
    EXPLOIT_MODULE = "exploit_module"  # a confirmation/exploitation module
    ORACLE = "oracle"                # a verification oracle
    POSTEX = "postex"                # a post-exploitation action (O3)
    PLANNED = "planned"              # mapped, not yet built


class TechniqueCapability(StrictModel):
    """How the engine performs/confirms a technique."""

    kind: CapabilityKind
    ref: str        # tool name / module id / oracle id / action / note
    status: str = "available"  # "available" | "planned"

    @property
    def available(self) -> bool:
        return self.status == "available" and self.kind is not CapabilityKind.PLANNED


class Technique(StrictModel):
    """An ATT&CK technique the engine references."""

    id: str                      # e.g. "T1190"
    name: str
    tactic: Tactic
    description: str = ""
    #: The engine capabilities that realize this technique (may be several).
    capabilities: tuple[TechniqueCapability, ...] = ()

    @property
    def available(self) -> bool:
        return any(c.available for c in self.capabilities)

    @property
    def reference(self) -> str:
        base = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"


class TechniqueLibrary:
    """Registry of techniques keyed by ATT&CK id."""

    def __init__(self) -> None:
        self._techniques: dict[str, Technique] = {}

    def register(self, technique: Technique, *, replace: bool = False) -> None:
        if technique.id in self._techniques and not replace:
            raise ValueError(f"technique {technique.id} already registered")
        self._techniques[technique.id] = technique

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id)

    def all(self) -> list[Technique]:
        return list(self._techniques.values())

    def by_tactic(self, tactic: Tactic) -> list[Technique]:
        return sorted(
            (t for t in self._techniques.values() if t.tactic is tactic),
            key=lambda t: t.id,
        )

    def available_ids(self) -> set[str]:
        return {t.id for t in self._techniques.values() if t.available}

    def __len__(self) -> int:
        return len(self._techniques)

    def __contains__(self, technique_id: object) -> bool:
        return technique_id in self._techniques
