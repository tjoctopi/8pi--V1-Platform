"""Attack-surface intelligence dossier tests."""

from __future__ import annotations

from attack_engine.intel.surface import build_attack_surface
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service


def _store() -> KnowledgeStore:
    store = KnowledgeStore("eng-intel")
    store.add_asset(Asset(
        address="10.5.0.10", engagement_id="eng-intel",
        services=(Service(port=80, name="http", product="Apache httpd", version="2.4.49"),
                  Service(port=3000, name="http")),
    ))
    return store


def _confirm(store, f):
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="oracle")
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def test_services_and_versions_captured() -> None:
    surface = build_attack_surface(_store())
    asset = surface.assets[0]
    ports = {s.port: (s.product, s.version) for s in asset.services}
    assert ports[80] == ("Apache httpd", "2.4.49")
    assert asset.reachable is True


def test_exposed_items_flagged_from_discovered_paths() -> None:
    store = _store()
    for p in ("admin", ".git/config", ".env", "assets/app.js"):
        store.propose_finding(Finding(engagement_id="eng-intel", asset="10.5.0.10",
                                      type=f"web-path:{p}", priority=Priority.INFORMATIONAL))
    surface = build_attack_surface(store)
    exposed = {e.path: e.category for e in surface.assets[0].exposed_items}
    assert ".git/config" in exposed and exposed[".git/config"] == "vcs"
    assert ".env" in exposed and exposed[".env"] == "secrets"
    assert "admin" in exposed
    assert "assets/app.js" not in exposed  # ordinary asset, not interesting


def test_attack_leads_confirmed_first_with_actions() -> None:
    store = _store()
    # A candidate SQLi lead + a confirmed one + a CVE.
    store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="sqli-candidate",
        metadata={"path": "/search", "param": "q"}))
    conf = store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="sqli-boolean-blind",
        exploit_prob=0.95, priority=Priority.HIGH,
        metadata={"path": "/rest/products/search", "param": "q"}))
    _confirm(store, conf)
    cve = store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="CVE-2021-41773",
        on_kev=True, exploit_prob=0.98, priority=Priority.PATCH_IMMEDIATELY,
        service="Apache httpd/2.4.49"))
    _confirm(store, cve)

    surface = build_attack_surface(store)
    leads = surface.assets[0].attack_leads
    classes = [ld.vuln_class for ld in leads]
    assert "sqli" in classes and "cve" in classes
    # Confirmed leads rank ahead of candidates.
    assert leads[0].status == "confirmed"
    # Every lead carries a concrete offensive next-step.
    assert all(ld.suggested_action for ld in leads)
    sqli_conf = next(ld for ld in leads if ld.vuln_class == "sqli" and ld.status == "confirmed")
    assert sqli_conf.location == "/rest/products/search?q="
    assert sqli_conf.technique == "T1190"
    cve_lead = next(ld for ld in leads if ld.vuln_class == "cve")
    assert cve_lead.on_kev is True
    assert "CVE-2021-41773" in surface.assets[0].cves


def test_endpoints_and_observations_captured() -> None:
    store = _store()
    store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="web-endpoint:/login.jsp",
        metadata={"path": "/login.jsp", "params": ["user", "pass"], "method": "POST"}))
    store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="web:prometheus-metrics",
        title="Prometheus Metrics", metadata={"severity": "medium"}))
    store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="web:missing-headers",
        title="Missing Security Headers", metadata={"severity": "info"}))
    surface = build_attack_surface(store)
    asset = surface.assets[0]
    login = next(e for e in asset.endpoints if e.path == "/login.jsp")
    assert login.method == "POST" and "user" in login.params
    assert "Prometheus Metrics" in asset.observations["medium"]
    assert "Missing Security Headers" in asset.observations["info"]


def test_markdown_is_offensive_oriented() -> None:
    store = _store()
    conf = store.propose_finding(Finding(
        engagement_id="eng-intel", asset="10.5.0.10", type="sqli-boolean-blind",
        exploit_prob=0.95, priority=Priority.HIGH,
        metadata={"path": "/x", "param": "q"}))
    _confirm(store, conf)
    md = build_attack_surface(store).to_markdown()
    assert "# Attack-Surface Intelligence" in md
    assert "Attack leads" in md
    assert "Suggested action" in md
    assert "10.5.0.10" in md
