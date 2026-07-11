"""Union-find finding de-duplication (spec §3 Verify, §5 Accuracy).

When independent tools report the same issue on the same asset, we must collapse
them into a single finding — otherwise the report double-counts and evidence
fusion is skewed. We use a disjoint-set (union-find) structure with path
compression and union-by-rank so clustering is near-constant time regardless of
how many tools report.

Two findings are unioned when they share a *dedup key* — by default
``(engagement, asset, normalized-type, injection-locus)``. The locus keeps two
*different* injection points of the same class on one host (e.g. SQLi in
``/search?q=`` vs ``/user?id=``) as distinct vulnerabilities — collapsing them
would hide real breach vectors — while still folding true duplicates (the same
point reported by two tools). The key is pluggable for fuzzier clustering later.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ..schemas.findings import Finding

DedupKey = Callable[[Finding], tuple[str, ...]]


def default_key(f: Finding) -> tuple[str, ...]:
    """Default clustering key: engagement + asset + type + injection locus.

    The *locus* (request path + parameter, when present) discriminates distinct
    insertion points that share a finding type on the same host. Findings with no
    such metadata (service/CVE/observation findings) get an empty locus, so their
    clustering is unchanged — this stays backward-compatible.
    """

    md = f.metadata or {}
    locus = (str(md.get("path") or "").strip().lower(),
             str(md.get("param") or "").strip().lower())
    return (f.engagement_id, f.asset.strip().lower(), f.type.strip().lower(), *locus)


class _DisjointSet:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def add(self, x: str) -> None:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression.
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        # Union by rank.
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1
        return ra


class DedupIndex:
    """Clusters findings by dedup key; each cluster has a stable representative.

    ``add`` returns the id of the cluster representative for the given finding
    (the first finding seen for that key). Callers merge evidence into the
    representative rather than storing near-duplicates.
    """

    def __init__(self, key: DedupKey = default_key) -> None:
        self._key = key
        self._ds = _DisjointSet()
        #: dedup-key tuple -> representative finding id
        self._key_to_rep: dict[tuple[str, ...], str] = {}
        #: finding id -> its dedup key
        self._id_to_key: dict[str, tuple[str, ...]] = {}

    def add(self, finding: Finding) -> str:
        """Register ``finding``; return the representative id for its cluster.

        If the returned id differs from ``finding.id``, this finding is a
        duplicate of an already-seen one.
        """

        key = self._key(finding)
        self._id_to_key[finding.id] = key
        self._ds.add(finding.id)
        rep = self._key_to_rep.get(key)
        if rep is None:
            self._key_to_rep[key] = finding.id
            return finding.id
        self._ds.union(rep, finding.id)
        return self._ds.find(rep)

    def representative(self, finding_id: str) -> str:
        return self._ds.find(finding_id)

    def is_duplicate(self, finding: Finding) -> bool:
        return self._key(finding) in self._key_to_rep

    def cluster_count(self) -> int:
        return len(self._key_to_rep)

    def cluster_members(self, ids: Iterable[str]) -> dict[str, list[str]]:
        """Group the given ids by their cluster representative."""

        clusters: dict[str, list[str]] = {}
        for fid in ids:
            clusters.setdefault(self._ds.find(fid), []).append(fid)
        return clusters
