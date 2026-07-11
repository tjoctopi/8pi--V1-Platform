"""Version parsing + interval matching tests (the #1 FP-source killer)."""

from __future__ import annotations

import pytest

from attack_engine.versioning import VersionRange, parse


class TestOrdering:
    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("2.4.49", "2.4.50"),
            ("2.4.9", "2.4.10"),  # numeric, not lexical
            ("1.0", "1.0.1"),
            ("2.4.49-rc1", "2.4.49"),  # pre-release < release
            ("1.2.3-alpha", "1.2.3-beta"),
            ("5.5.61", "5.6.0"),
        ],
    )
    def test_less_than(self, a: str, b: str) -> None:
        assert parse(a) < parse(b)
        assert parse(b) > parse(a)

    def test_equality_with_padding(self) -> None:
        assert parse("2.4") == parse("2.4.0")
        assert parse("1.0.0") == parse("1.0")

    def test_numeric_not_lexical(self) -> None:
        # The classic bug: "9" < "10" numerically, but "9" > "10" lexically.
        assert parse("2.4.9") < parse("2.4.10")

    def test_banner_suffixes_parse(self) -> None:
        # e.g. MySQL "5.5.61-log" — the -log suffix must not break comparison.
        assert parse("5.5.61-log") <= parse("5.5.61")
        assert parse("5.5.61-log").release == (5, 5, 61)


class TestVersionRange:
    def test_fixed_is_exclusive_upper_bound(self) -> None:
        # CVE-2021-41773: introduced 2.4.49, fixed 2.4.50.
        rng = VersionRange.build(introduced="2.4.49", fixed="2.4.50")
        assert rng.contains("2.4.49")  # vulnerable
        assert not rng.contains("2.4.50")  # fixed — must NOT match (the FP)
        assert not rng.contains("2.4.48")  # too old, not introduced yet

    def test_last_affected_is_inclusive(self) -> None:
        rng = VersionRange.build(last_affected="2.4.49")
        assert rng.contains("2.4.49")
        assert rng.contains("2.4.0")
        assert not rng.contains("2.4.50")

    def test_open_lower_bound(self) -> None:
        rng = VersionRange.build(fixed="1.1.0")
        assert rng.contains("0.9")
        assert rng.contains("1.0.99")
        assert not rng.contains("1.1.0")

    def test_open_upper_bound(self) -> None:
        rng = VersionRange.build(introduced="2.0")
        assert not rng.contains("1.9")
        assert rng.contains("2.0")
        assert rng.contains("99.0")

    def test_cannot_set_both_fixed_and_last_affected(self) -> None:
        with pytest.raises(ValueError, match="only one"):
            VersionRange.build(fixed="1.0", last_affected="1.0")

    def test_prerelease_boundary(self) -> None:
        rng = VersionRange.build(introduced="2.4.49", fixed="2.4.50")
        # A release-candidate of the fixed version is still vulnerable.
        assert rng.contains("2.4.50-rc1")


def test_version_is_hashable_and_sortable() -> None:
    versions = [parse("2.4.50"), parse("2.4.9"), parse("2.4.10"), parse("2.4.49")]
    ordered = [str(v) for v in sorted(versions)]
    assert ordered == ["2.4.9", "2.4.10", "2.4.49", "2.4.50"]
    assert isinstance(hash(parse("1.0")), int)
