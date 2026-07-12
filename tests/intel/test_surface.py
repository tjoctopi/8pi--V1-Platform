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
    by_name = {o.name: o for o in asset.observations}
    assert by_name["Prometheus Metrics"].severity == "medium"
    assert by_name["Missing Security Headers"].severity == "info"
    # Medium/info observations need no corroboration — reported as-is.
    assert by_name["Prometheus Metrics"].confidence == "reported"


def test_uncorroborated_critical_is_flagged_unconfirmed() -> None:
    # Reproduces the ggi false positive: a critical "VMware ESXi SLP" match on an
    # nginx-only asset. Nothing in the fingerprint mentions vmware/esxi/slp, so it
    # must be tagged unconfirmed — never surfaced as a confirmed critical.
    store = KnowledgeStore("eng-fp")
    store.add_asset(Asset(
        address="www.example.com", engagement_id="eng-fp",
        services=(Service(port=443, name="https", product="nginx"),),
    ))
    store.propose_finding(Finding(
        engagement_id="eng-fp", asset="www.example.com",
        type="web:vmware-esxi-slp-heap-overflow", title="VMware ESXi SLP - Heap Overflow DoS",
        metadata={"severity": "critical"}))
    surface = build_attack_surface(store)
    obs = {o.name: o for o in surface.assets[0].observations}
    esxi = obs["VMware ESXi SLP - Heap Overflow DoS"]
    assert esxi.confidence == "unconfirmed"
    md = surface.to_markdown()
    assert "unconfirmed" in md
    # The bogus critical must NOT be presented as corroborated.
    assert "(corroborated): VMware ESXi" not in md


def test_corroborated_critical_keeps_severity() -> None:
    # A WordPress-tech asset with a matching WordPress critical IS corroborated.
    store = KnowledgeStore("eng-tp")
    store.add_asset(Asset(
        address="blog.example.com", engagement_id="eng-tp",
        services=(Service(port=443, name="https", product="Apache", banner="WordPress"),),
    ))
    store.propose_finding(Finding(
        engagement_id="eng-tp", asset="blog.example.com",
        type="web:wordpress-rce", title="WordPress core RCE",
        metadata={"severity": "critical"}))
    surface = build_attack_surface(store)
    obs = surface.assets[0].observations[0]
    assert obs.confidence == "corroborated"


def test_edge_and_coverage_surfaced() -> None:
    store = KnowledgeStore("eng-edge")
    store.add_asset(Asset(address="www.example.com", engagement_id="eng-edge"))
    store.propose_finding(Finding(
        engagement_id="eng-edge", asset="www.example.com",
        type="web-edge:cloudflare", title="Fronted by Cloudflare CDN/WAF",
        metadata={"is_cdn": True, "is_waf": True, "vendor": "Cloudflare"}))
    store.record_tool_run("nuclei", "www.example.com", "ok")
    store.record_tool_run("dalfox", "www.example.com", "degraded", "timeout after 600s")
    store.record_tool_run("dalfox", "www.example.com", "skipped", "lead-gated")
    surface = build_attack_surface(store)
    assert surface.assets[0].edge == "Cloudflare CDN/WAF"
    cov = {h.tool: h for h in surface.coverage}
    assert cov["dalfox"].degraded == 1 and cov["dalfox"].skipped == 1
    md = surface.to_markdown()
    assert "Coverage / tool health" in md
    assert "Cloudflare" in md and "degraded" in md.lower()


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
