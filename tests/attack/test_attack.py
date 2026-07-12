"""MITRE ATT&CK library, catalog mapping, and coverage (O4) tests."""

from __future__ import annotations

import pytest

from attack_engine.attack import (
    Tactic,
    build_coverage,
    build_library,
    technique_for_finding_type,
)
from attack_engine.attack.technique import CapabilityKind


def test_library_registers_catalog() -> None:
    lib = build_library()
    assert len(lib) >= 20
    assert "T1190" in lib and "T1059" in lib and "T1078" in lib
    t = lib.get("T1190")
    assert t is not None and t.tactic is Tactic.INITIAL_ACCESS


def test_available_vs_planned() -> None:
    lib = build_library()
    # T1190 has real capabilities (oracle/module/tool) → available.
    assert lib.get("T1190").available is True
    # T1068 (privesc) is only mapped as planned (O5) → not available.
    t1068 = lib.get("T1068")
    assert t1068.available is False
    assert all(c.kind is CapabilityKind.PLANNED for c in t1068.capabilities)
    assert "T1190" in lib.available_ids() and "T1068" not in lib.available_ids()


@pytest.mark.parametrize(("ftype", "technique"), [
    ("sqli-boolean-blind", "T1190"),
    ("path-traversal", "T1190"),
    ("rce", "T1190"),
    ("command-injection", "T1059"),
    ("cmdi-candidate", "T1059"),
    ("ssti", "T1221"),
    ("xss-reflected:q", "T1059.007"),
    ("xss-candidate", "T1059.007"),
    ("open-redirect-candidate", "T1204.001"),
    ("default-cred", "T1078"),
    ("CVE-2021-41773", "T1190"),
    ("something-unknown", "T1190"),  # sensible default
])
def test_finding_type_to_technique(ftype: str, technique: str) -> None:
    assert technique_for_finding_type(ftype) == technique


def test_technique_reference_url() -> None:
    lib = build_library()
    assert lib.get("T1190").reference == "https://attack.mitre.org/techniques/T1190/"
    assert lib.get("T1595.002").reference == "https://attack.mitre.org/techniques/T1595/002/"


def test_coverage_report_counts_and_markdown() -> None:
    lib = build_library()
    cov = build_coverage(lib)
    assert cov.available_count + cov.planned_count == cov.total == len(lib)
    assert cov.available_count == len(lib.available_ids())
    md = cov.to_markdown()
    assert "ATT&CK Coverage" in md
    assert "Initial Access" in md and "Reconnaissance" in md
    # Impact techniques are mapped but always planned (never autonomous).
    impact = next(tc for tc in cov.tactics if tc.tactic_id == Tactic.IMPACT.value)
    assert impact.available == [] and impact.planned


def test_builtin_profiles_have_ordered_kill_chains() -> None:
    from attack_engine.orchestrator.profiles import BUILTIN_PROFILES

    lib = build_library()
    for prof in BUILTIN_PROFILES.values():
        assert prof.kill_chain, f"{prof.id} has no kill chain"
        assert "exploit_confirm" in prof.techniques
        # Every technique in the emulation chain is a real, catalogued technique.
        for tid in prof.kill_chain:
            assert tid in lib, f"{prof.id} references unknown technique {tid}"
