"""Web-service classification tests (any-port, service-name aware)."""

from __future__ import annotations

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.netutil import web_scheme, web_targets
from attack_engine.schemas.findings import Asset, Service


def test_scheme_by_service_name_on_any_port() -> None:
    # A web app on a non-standard port is still recognised via its service name.
    assert web_scheme(Service(port=8081, name="http")) == "http"
    assert web_scheme(Service(port=9443, name="ssl/http")) == "https"
    assert web_scheme(Service(port=4443, name="https-alt")) == "https"
    # Well-known ports work even without a service name (bare -sT scan).
    assert web_scheme(Service(port=443, name=None)) == "https"
    assert web_scheme(Service(port=80, name=None)) == "http"
    # Non-web services are excluded.
    assert web_scheme(Service(port=22, name="ssh")) is None
    assert web_scheme(Service(port=3306, name="mysql")) is None


def test_web_targets_only_reachable_deduped() -> None:
    store = KnowledgeStore("eng-net")
    store.add_asset(Asset(address="10.0.0.1", engagement_id="eng-net",
                          services=(Service(port=8081, name="http"),
                                    Service(port=22, name="ssh"))))
    store.add_asset(Asset(address="10.0.0.2", engagement_id="eng-net",
                          services=(Service(port=443, name="https"),)),
                    reachable_from_entry=False)
    targets = web_targets(store)
    assert targets == ["http://10.0.0.1:8081"]  # ssh excluded, unreachable host excluded
