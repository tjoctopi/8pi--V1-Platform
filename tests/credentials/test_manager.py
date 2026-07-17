"""Credential manager — governed capture → crack → own, feeding the AD graph."""

from __future__ import annotations

from attack_engine.ad.graph import ADEdgeType, ADGraph, PrincipalKind
from attack_engine.credentials.manager import CredentialManager
from attack_engine.governance.audit import AuditLog
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.credentials import CredentialState, SecretKind

# Genuine impacket-generated Kerberoast blob for password "Summer2026!" (see cracker test).
_TGS = (
    "$krb5tgs$23$*svc_sql*CORP.LOCAL*MSSQL/db*$"
    "5bf73a77ffb2392433271d4b7c2fc8d1$"
    "364a207fe91c05e8eaeaf5d775c6bdf726f9edd61276cd52b62d8fcdcab9"
)
_NT = "41aed72cec76816423703d8e545eea31"
_WORDLIST = ["Winter2025", "Summer2026!", "admin"]


def _mgr() -> tuple[CredentialManager, AuditLog]:
    audit = AuditLog()
    return CredentialManager("eng-e3", audit), audit


def test_capture_stores_material_in_vault_not_model() -> None:
    mgr, audit = _mgr()
    cred = mgr.capture("svc_sql@CORP.LOCAL", SecretKind.KERBEROS_TGS, _TGS, source="kerberoast")
    assert cred.state is CredentialState.CAPTURED
    assert cred.secret_ref.startswith("vault-")
    # The model never carries the raw material — only a ref + mask.
    assert _TGS not in cred.model_dump_json()
    assert mgr.vault.get(cred.secret_ref) == _TGS
    # Captured, audited, and no raw material in the audit payload.
    entry = audit.entries("eng-e3")[-1]
    assert entry.action == "credential.captured"
    assert _TGS not in str(entry.payload)


def test_crack_mints_reusable_plaintext_credential() -> None:
    mgr, audit = _mgr()
    roast = mgr.capture("svc_sql", SecretKind.KERBEROS_TGS, _TGS, source="kerberoast")
    assert not roast.is_reusable  # a roast blob is not usable until cracked

    cracked = mgr.crack(roast, _WORDLIST)
    assert cracked is not None
    assert cracked.kind is SecretKind.PLAINTEXT
    assert cracked.state is CredentialState.CRACKED
    assert cracked.is_reusable
    assert cracked.source == "cracked"
    # Plaintext lives only in the vault, never in the model or the audit log.
    assert "Summer2026!" not in cracked.model_dump_json()
    assert mgr.vault.get(cracked.secret_ref) == "Summer2026!"
    assert any(e.action == "credential.cracked" for e in audit.entries("eng-e3"))
    assert all("Summer2026!" not in str(e.payload) for e in audit.entries("eng-e3"))


def test_crack_nt_hash() -> None:
    mgr, _ = _mgr()
    cred = mgr.capture("alice", SecretKind.NT_HASH, _NT, source="dcsync")
    cracked = mgr.crack(cred, _WORDLIST)
    assert cracked is not None and cracked.is_reusable


def test_crack_failure_returns_none_and_audits() -> None:
    mgr, audit = _mgr()
    roast = mgr.capture("svc_sql", SecretKind.KERBEROS_TGS, _TGS)
    assert mgr.crack(roast, ["wrong", "nope"]) is None
    assert any(e.action == "credential.crack.failed" for e in audit.entries("eng-e3"))


def test_own_reusable_credential_marks_principal_and_audits() -> None:
    mgr, audit = _mgr()
    wm = WorldModel("eng-e3")
    cred = mgr.capture("svc_sql", SecretKind.NT_HASH, _NT, source="dcsync")

    assert mgr.own(cred, wm) is True          # newly owned
    assert "SVC_SQL" in wm.owned_principals
    assert mgr.own(cred, wm) is False         # already owned
    assert any(e.action == "credential.owned" for e in audit.entries("eng-e3"))


def test_cannot_own_a_roast_blob_before_cracking() -> None:
    mgr, _ = _mgr()
    wm = WorldModel("eng-e3")
    roast = mgr.capture("svc_sql", SecretKind.KERBEROS_TGS, _TGS)
    assert mgr.own(roast, wm) is False        # must crack first
    assert wm.owned_principals == []


def test_lifecycle_owning_cracked_account_surfaces_a_new_da_path() -> None:
    """The escalate loop: crack a service account → own it → a path to DA appears."""

    # A forest where svc_sql holds GenericAll over Domain Admins.
    graph = ADGraph()
    graph.add_principal("svc_sql", PrincipalKind.USER)
    graph.add_principal("Domain Admins", PrincipalKind.GROUP, high_value=True)
    graph.add_edge("SVC_SQL", "DOMAIN ADMINS", ADEdgeType.GENERIC_ALL)

    wm = WorldModel("eng-e3")
    wm.set_ad_graph(graph)
    assert wm.domain_admin_paths() == []      # nothing owned yet → no path

    mgr, _ = _mgr()
    roast = mgr.capture("svc_sql", SecretKind.KERBEROS_TGS, _TGS, source="kerberoast")
    cracked = mgr.crack(roast, _WORDLIST)
    assert cracked is not None
    mgr.own(cracked, wm)

    paths = wm.domain_admin_paths()
    assert paths, "owning the cracked account should surface a path to Domain Admins"
    assert paths[0].start == "SVC_SQL"
    assert paths[0].target == "DOMAIN ADMINS"
