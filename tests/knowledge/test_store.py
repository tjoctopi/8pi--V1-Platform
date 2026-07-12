"""Knowledge store (blackboard) tests: ingest, dedup, lifecycle, events."""

from __future__ import annotations

import pytest

from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.schemas.events import Event, EventType
from attack_engine.schemas.findings import Asset, Finding, FindingState, Service


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def store(bus: InMemoryEventBus):
    from attack_engine.knowledge.store import KnowledgeStore

    return KnowledgeStore("eng-1", event_bus=bus)


def asset(addr: str, ports: list[int] | None = None) -> Asset:
    svcs = tuple(Service(port=p, name="http") for p in (ports or []))
    return Asset(address=addr, services=svcs, engagement_id="eng-1")


class TestAssets:
    def test_add_asset_emits_discovery_events(self, store, bus) -> None:
        events: list[Event] = []
        bus.subscribe(events.append)
        store.add_asset(asset("10.0.4.12", [80, 443]), emitted_by="mapper")
        types = [e.event for e in events]
        assert types.count(EventType.ASSET_DISCOVERED) == 1
        assert types.count(EventType.SERVICE_DISCOVERED) == 2

    def test_re_adding_same_address_merges_not_duplicates(self, store) -> None:
        store.add_asset(asset("10.0.4.12", [80]))
        store.add_asset(asset("10.0.4.12", [443]))
        assert len(store.assets()) == 1
        merged = store.get_asset("10.0.4.12")
        assert {s.port for s in merged.services} == {80, 443}

    def test_richer_service_record_supersedes(self, store) -> None:
        store.add_asset(asset("10.0.4.12", [80]))  # bare port
        detailed = Asset(
            address="10.0.4.12",
            services=(Service(port=80, product="Apache httpd", version="2.4.49"),),
            engagement_id="eng-1",
        )
        store.add_asset(detailed)
        svc = next(s for s in store.get_asset("10.0.4.12").services if s.port == 80)
        assert svc.version == "2.4.49"

    def test_second_add_same_address_emits_only_new_services(self, store, bus) -> None:
        store.add_asset(asset("10.0.4.12", [80]))
        events: list[Event] = []
        bus.subscribe(events.append)
        store.add_asset(asset("10.0.4.12", [80, 443]))  # 80 known, 443 new
        types = [e.event for e in events]
        assert EventType.ASSET_DISCOVERED not in types
        assert types.count(EventType.SERVICE_DISCOVERED) == 1

    def test_engagement_mismatch_rejected(self, store) -> None:
        with pytest.raises(ValueError, match="engagement"):
            store.add_asset(Asset(address="1.2.3.4", engagement_id="eng-OTHER"))


class TestFindings:
    def test_propose_stores_and_emits(self, store, bus) -> None:
        events: list[Event] = []
        bus.subscribe(events.append, event_types=[EventType.FINDING_PROPOSED])
        f = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="open-port"),
            emitted_by="mapper",
        )
        assert store.get_finding(f.id) is not None
        assert len(events) == 1

    def test_duplicate_finding_merges_evidence(self, store) -> None:
        f1 = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="cve-x",
                    evidence=("raw:audit-1",))
        )
        f2 = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="cve-x",
                    evidence=("raw:audit-2",))
        )
        assert f2.id == f1.id  # returned representative
        assert set(f2.evidence) == {"raw:audit-1", "raw:audit-2"}
        assert len(store.findings()) == 1

    def test_reachability_derived_from_graph(self, store) -> None:
        store.add_asset(asset("10.0.4.12", [80]))
        f = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="open-port")
        )
        assert f.reachable is True

    def test_finding_for_unknown_asset_is_not_reachable(self, store) -> None:
        f = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.9.9", type="open-port")
        )
        assert f.reachable is False

    def test_promote_lifecycle_and_events(self, store, bus) -> None:
        events: list[Event] = []
        bus.subscribe(events.append)
        f = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="cve-x")
        )
        v = store.promote_finding(f.id, FindingState.VERIFIED, verified_by="oracle-1")
        c = store.promote_finding(v.id, FindingState.CONFIRMED)
        assert c.state is FindingState.CONFIRMED
        assert c.verified_by == "oracle-1"
        types = [e.event for e in events]
        assert EventType.FINDING_VERIFIED in types
        assert EventType.FINDING_CONFIRMED in types

    def test_illegal_promotion_blocked(self, store) -> None:
        f = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="cve-x")
        )
        with pytest.raises(ValueError, match="illegal finding transition"):
            store.promote_finding(f.id, FindingState.CONFIRMED)

    def test_findings_filter_by_state(self, store) -> None:
        f1 = store.propose_finding(
            Finding(engagement_id="eng-1", asset="10.0.4.12", type="a")
        )
        store.propose_finding(Finding(engagement_id="eng-1", asset="10.0.4.13", type="b"))
        store.promote_finding(f1.id, FindingState.VERIFIED, verified_by="o")
        assert len(store.findings(FindingState.PROPOSED)) == 1
        assert len(store.findings(FindingState.VERIFIED)) == 1


class TestToolCoverage:
    def test_record_and_read_tool_runs(self, store) -> None:
        store.record_tool_run("nmap", "10.0.4.12", "ok")
        store.record_tool_run("dalfox", "10.0.4.12", "degraded", "timeout after 600s")
        runs = store.tool_runs()
        assert len(runs) == 2
        degraded = [r for r in runs if r.outcome == "degraded"]
        assert degraded[0].tool == "dalfox" and "timeout" in degraded[0].detail


class TestCrossRunMerge:
    def test_export_import_unions_services(self, store) -> None:
        # Prior run saw port 81; this run's fresh store only saw 80.
        prior = store  # stand-in for a previous engagement store
        prior.add_asset(asset("10.0.4.12", [80, 81]))
        exported = prior.export_assets()

        from attack_engine.knowledge.store import KnowledgeStore
        fresh = KnowledgeStore("eng-1")
        fresh.add_asset(asset("10.0.4.12", [80]))
        n = fresh.import_assets(exported)
        assert n == 1
        ports = {s.port for a in fresh.assets() for s in a.services}
        assert ports == {80, 81}  # port 81 from the prior run survived


def test_stats_snapshot(store) -> None:
    store.add_asset(asset("10.0.4.12", [80, 443]))
    store.propose_finding(Finding(engagement_id="eng-1", asset="10.0.4.12", type="x"))
    stats = store.stats()
    assert stats["assets"] == 1
    assert stats["services"] == 2
    assert stats["findings"] == 1
