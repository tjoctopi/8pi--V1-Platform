"""Injection insertion-point discovery (breachability detection input).

To decide whether a web target is *actually breachable*, the engine has to test
concrete injection points — a (path, parameter) pair a request parameter flows
into. This module assembles that candidate set from three complementary sources,
so detection is discovery-driven rather than a fixed guess:

1. **Leads already on the blackboard** — ``sqli-candidate`` findings raised by
   the crawler (Katana) or a templated scanner (Nuclei ``matched-at`` with a
   query parameter). These are the highest-signal points: something already
   pointed at them.
2. **Discovered surface** — ``web-path:`` findings from content discovery
   (ffuf). A discovered API root (``/rest``, ``/api``…) is expanded with the
   common REST insertion points that sit under such roots; other discovered
   paths are parameterised with the usual identifier/query parameters.
3. **A generic seed catalog** — the common web/API insertion points every
   scanner ships with (search ``q``, resource ``id``, …), so a target with a
   thin crawl surface is still probed at the usual places.

The result is deduplicated (path, param, method) points. Each is *screened* and,
if suspicious, proposed as a hypothesis for the read-only SQLi oracle to confirm
— the module itself asserts nothing (rule #1).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..knowledge.store import KnowledgeStore
from ..schemas.findings import Finding


@dataclass(frozen=True)
class InjectionPoint:
    """A concrete place to test for injection: ``path`` + a single ``param``."""

    scheme: str
    port: int | None
    path: str
    param: str
    base_value: str = "1"
    method: str = "GET"

    def key(self) -> tuple[str, str, str]:
        """Dedup identity — a point is the same regardless of base value."""

        return (self.path, self.param, self.method)


#: Common query parameters an identifier/search value flows into.
_ID_PARAMS = ("id", "productId", "userId", "pid", "uid")
_SEARCH_PARAMS = ("q", "query", "search", "term", "name", "keyword")

#: Generic insertion points present in a large fraction of web apps / APIs. Not
#: target-specific: these are the "usual places" a scanner always checks. Extend
#: per engagement with app-specific knowledge (or let discovery drive it).
_SEED_CATALOG: tuple[tuple[str, str, str], ...] = (
    # (path, param, base_value)
    ("/rest/products/search", "q", "apple"),
    ("/api/products/search", "q", "apple"),
    ("/products/search", "q", "apple"),
    ("/search", "q", "test"),
    ("/search", "query", "test"),
    ("/api/search", "q", "test"),
    ("/product", "id", "1"),
    ("/products", "id", "1"),
    ("/user", "id", "1"),
    ("/users", "id", "1"),
    ("/rest/user", "id", "1"),
    ("/api/user", "id", "1"),
    ("/item", "id", "1"),
    ("/article", "id", "1"),
    ("/news", "id", "1"),
    ("/category", "cat", "1"),
    ("/index.php", "id", "1"),
    ("/page", "id", "1"),
)

#: Discovered API roots are expanded with these (relative path, param, base).
_REST_ROOTS = ("rest", "api", "api/v1", "api/v2", "graphql", "v1", "v2")
_REST_EXPANSIONS: tuple[tuple[str, str, str], ...] = (
    ("products/search", "q", "apple"),
    ("users", "id", "1"),
    ("user", "id", "1"),
    ("products", "id", "1"),
    ("search", "q", "test"),
)


def _host_findings(store: KnowledgeStore, host: str, prefix: str) -> list[Finding]:
    return [
        f
        for f in store.findings()
        if f.asset == host and f.type.startswith(prefix)
    ]


def _from_candidates(
    store: KnowledgeStore, host: str, scheme: str, port: int | None
) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    for f in _host_findings(store, host, "sqli-candidate"):
        md = f.metadata
        param = md.get("param")
        path = md.get("path")
        if not param or not path:
            continue
        points.append(
            InjectionPoint(
                scheme=str(md.get("scheme") or scheme),
                port=md.get("port") if md.get("port") is not None else port,
                path=str(path),
                param=str(param),
                base_value=str(md.get("base_value", "1")),
                method=str(md.get("method", "GET")).upper(),
            )
        )
    return points


def _from_discovered_paths(
    store: KnowledgeStore, host: str, scheme: str, port: int | None
) -> list[InjectionPoint]:
    """Expand ffuf-discovered paths into concrete insertion points."""

    points: list[InjectionPoint] = []
    for f in _host_findings(store, host, "web-path:"):
        raw = f.type[len("web-path:"):].strip("/")
        if not raw:
            continue
        if raw in _REST_ROOTS:
            # A discovered API root → probe the common REST insertion points.
            for rel, param, base in _REST_EXPANSIONS:
                points.append(
                    InjectionPoint(scheme, port, f"/{raw}/{rel}", param, base)
                )
        elif "." not in raw.rsplit("/", 1)[-1]:
            # A discovered path with no file extension → parameterise it.
            for param in (_ID_PARAMS[0], _SEARCH_PARAMS[0]):
                base = "1" if param in _ID_PARAMS else "test"
                points.append(InjectionPoint(scheme, port, f"/{raw}", param, base))
    return points


def _from_catalog(scheme: str, port: int | None) -> list[InjectionPoint]:
    return [
        InjectionPoint(scheme, port, path, param, base)
        for path, param, base in _SEED_CATALOG
    ]


def build_injection_points(
    store: KnowledgeStore,
    host: str,
    scheme: str,
    port: int | None,
    *,
    limit: int = 64,
) -> list[InjectionPoint]:
    """Assemble a deduplicated, bounded set of injection points to screen.

    Ordered by signal: blackboard leads first, then discovered-surface
    expansions, then the generic seed catalog — so the most promising points are
    screened first and the ``limit`` (a safety bound on probe volume) favours
    them.
    """

    ordered = (
        _from_candidates(store, host, scheme, port)
        + _from_discovered_paths(store, host, scheme, port)
        + _from_catalog(scheme, port)
    )
    seen: set[tuple[str, str, str]] = set()
    unique: list[InjectionPoint] = []
    for point in ordered:
        k = point.key()
        if k in seen:
            continue
        seen.add(k)
        unique.append(point)
        if len(unique) >= limit:
            break
    return unique
