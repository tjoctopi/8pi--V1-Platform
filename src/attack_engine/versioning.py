"""Version comparison and affected-range interval matching (spec §5).

Naive string matching against CVE affected-version text is the #1 source of
scanner false positives ("Apache 2.4.49" flagged for a CVE that was fixed in
2.4.49). We model affected versions as proper half-open/closed **intervals**
and compare with a tolerant, deterministic version parser that handles the
messy real-world strings tools emit (``2.4.49``, ``1.2.3-rc1``, ``5.5.61-log``).

The parser is intentionally *not* strict PEP 440 / SemVer — service banners
rarely are. It splits into numeric and alphanumeric components, compares
numerics numerically, and treats a pre-release suffix as *older* than the same
release without one (``2.4.49-rc1 < 2.4.49``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

# A release segment is a run of digits or a run of non-digits.
_SEGMENT_RE = re.compile(r"\d+|[A-Za-z]+")
_PRERELEASE_TOKENS = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot"}


@total_ordering
@dataclass(frozen=True)
class Version:
    """A parsed, comparable version.

    ``release`` is the tuple of leading numeric components; ``prerelease`` marks
    a lower-precedence suffix. Comparison follows: compare release tuples
    component-wise (shorter padded with zeros); if equal, a version *with* a
    pre-release sorts *before* one without.
    """

    raw: str
    release: tuple[int, ...]
    prerelease: tuple[object, ...]

    @classmethod
    def parse(cls, text: str) -> Version:
        raw = text.strip()
        segments = _SEGMENT_RE.findall(raw.lower())
        release: list[int] = []
        prerelease: list[object] = []
        seen_prerelease = False
        for seg in segments:
            if seg.isdigit():
                if seen_prerelease:
                    prerelease.append(int(seg))
                else:
                    release.append(int(seg))
            else:
                # First alphabetic token flips us into the pre-release tail.
                seen_prerelease = True
                prerelease.append(seg)
        if not release:
            release = [0]
        return cls(raw=raw, release=tuple(release), prerelease=tuple(prerelease))

    def _release_padded(self, length: int) -> tuple[int, ...]:
        return self.release + (0,) * (length - len(self.release))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        n = max(len(self.release), len(other.release))
        return (
            self._release_padded(n) == other._release_padded(n)
            and self._prerelease_key() == other._prerelease_key()
        )

    def _prerelease_key(self) -> tuple[object, ...]:
        # No pre-release sorts AFTER any pre-release, so give "release" a
        # sentinel that is greater than any real pre-release token.
        if not self.prerelease:
            return (1,)
        # (0, ...tokens) so any pre-release < release; tokens compared as
        # (type_rank, value) to avoid str/int comparison errors.
        key: list[object] = [0]
        for tok in self.prerelease:
            if isinstance(tok, int):
                key.append((1, tok))
            else:
                rank = 0 if tok in _PRERELEASE_TOKENS else 2
                key.append((rank, tok))
        return tuple(key)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        n = max(len(self.release), len(other.release))
        a, b = self._release_padded(n), other._release_padded(n)
        if a != b:
            return a < b
        return self._prerelease_key() < other._prerelease_key()

    def __str__(self) -> str:
        return self.raw


def parse(text: str) -> Version:
    return Version.parse(text)


@dataclass(frozen=True)
class VersionRange:
    """A half-open/closed affected-version interval.

    ``[introduced, fixed)`` semantics by default: a version is affected when
    ``introduced <= v`` (if set) and ``v < fixed`` (if set). ``last_affected``
    (inclusive) is supported as an alternative upper bound, matching how CVE
    feeds express ranges.
    """

    introduced: Version | None = None
    fixed: Version | None = None
    last_affected: Version | None = None

    @classmethod
    def build(
        cls,
        *,
        introduced: str | None = None,
        fixed: str | None = None,
        last_affected: str | None = None,
    ) -> VersionRange:
        if fixed is not None and last_affected is not None:
            raise ValueError("specify only one of 'fixed' (exclusive) or 'last_affected'")
        return cls(
            introduced=parse(introduced) if introduced else None,
            fixed=parse(fixed) if fixed else None,
            last_affected=parse(last_affected) if last_affected else None,
        )

    def contains(self, version: Version | str) -> bool:
        v = parse(version) if isinstance(version, str) else version
        if self.introduced is not None and v < self.introduced:
            return False
        if self.fixed is not None and not (v < self.fixed):
            return False
        return not (self.last_affected is not None and v > self.last_affected)
