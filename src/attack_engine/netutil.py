"""Small network helpers shared across the engine (no external deps).

Web-service classification lives here so recon-driven components (orchestrator,
CLI ``intel``) agree on *what counts as a web surface* — by the scanner's service
name first (so a web app on any port is found), falling back to well-known ports.
"""

from __future__ import annotations

from .knowledge.store import KnowledgeStore
from .schemas.findings import Asset, Service

#: Well-known web ports and their default scheme (fallback when the service name
#: is unknown — e.g. a bare ``-sT`` scan without version detection).
WEB_PORTS: dict[int, str] = {
    80: "http", 8080: "http", 8000: "http", 8008: "http", 3000: "http",
    5000: "http", 8888: "http", 9000: "http", 443: "https", 8443: "https",
}

#: nmap/httpx service-name fragments that indicate an HTTP(S) surface.
_HTTP_NAMES = ("http", "www", "webcache", "web")


def web_scheme(service: Service) -> str | None:
    """Return ``"http"``/``"https"`` if ``service`` is a web surface, else None.

    Prefers the detected service name (works on *any* port), then TLS/known-port
    heuristics — so `8081/http` or `4443/https-alt` are recognised, not just 80/443.
    """

    name = (service.name or "").lower()
    if "https" in name or "ssl" in name or "tls" in name:
        return "https"
    if any(frag in name for frag in _HTTP_NAMES):
        # A named HTTP service on a TLS-ish port is still https.
        return "https" if service.port in (443, 8443, 4443) else "http"
    return WEB_PORTS.get(service.port)


def web_targets(store: KnowledgeStore) -> list[str]:
    """URL targets for every reachable web service discovered in recon."""

    urls: list[str] = []
    seen: set[str] = set()
    for asset in store.assets():
        if not store.graph.is_reachable(asset.id):
            continue
        for svc in asset.services:
            scheme = web_scheme(svc)
            if scheme is None:
                continue
            url = f"{scheme}://{asset.address}:{svc.port}"
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def web_targets_for_asset(asset: Asset) -> list[str]:
    """URL targets for the web services on a single asset (order-stable)."""

    urls: list[str] = []
    for svc in asset.services:
        scheme = web_scheme(svc)
        if scheme is not None:
            urls.append(f"{scheme}://{asset.address}:{svc.port}")
    return urls
