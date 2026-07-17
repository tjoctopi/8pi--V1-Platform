"""Credential vault — opaque refs, masked previews, no raw leakage."""

from __future__ import annotations

from attack_engine.credentials.vault import CredentialVault, mask


def test_put_get_roundtrip() -> None:
    vault = CredentialVault()
    ref = vault.put("Summer2026!")
    assert vault.has(ref)
    assert vault.get(ref) == "Summer2026!"
    assert len(vault) == 1


def test_ref_is_opaque_not_the_secret() -> None:
    vault = CredentialVault()
    ref = vault.put("supersecret")
    assert "supersecret" not in ref
    assert ref.startswith("vault-")


def test_get_unknown_ref_raises() -> None:
    vault = CredentialVault()
    try:
        vault.get("vault-does-not-exist")
    except KeyError as exc:
        assert "unknown credential ref" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected KeyError")


def test_preview_is_masked_never_raw() -> None:
    vault = CredentialVault()
    ref = vault.put("Summer2026!")
    preview = vault.preview(ref)
    assert "Summer2026!" not in preview
    assert preview == "Sum…****"


def test_preview_unknown_ref_is_fully_redacted() -> None:
    assert CredentialVault().preview("nope") == "****"


def test_purge_removes_material() -> None:
    vault = CredentialVault()
    ref = vault.put("x")
    assert vault.purge(ref) is True
    assert not vault.has(ref)
    assert vault.purge(ref) is False  # already gone


def test_mask_short_secret_fully_redacted() -> None:
    assert mask("abcd") == "****"
    assert mask("") == "****"


def test_mask_long_secret_shows_prefix_only() -> None:
    masked = mask("Password123")
    assert masked == "Pas…****"
    assert "Password123" not in masked
