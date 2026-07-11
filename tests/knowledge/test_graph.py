"""Attack graph reachability + path tests."""

from __future__ import annotations

import pytest

from attack_engine.errors import UnknownNodeError
from attack_engine.knowledge.graph import ENTRY_NODE, AttackGraph
from attack_engine.schemas.findings import Asset, Service


def asset(addr: str, ports: list[int] | None = None, eng: str = "eng-1") -> Asset:
    svcs = tuple(Service(port=p, name="http") for p in (ports or []))
    return Asset(address=addr, services=svcs, engagement_id=eng)


def test_discovered_asset_is_reachable_from_entry() -> None:
    g = AttackGraph()
    a = asset("10.0.4.12", [80, 443])
    g.add_asset(a)
    assert a.id in g.reachable_assets()
    assert g.is_reachable(a.id)


def test_unreachable_asset_when_no_edge() -> None:
    g = AttackGraph()
    a = asset("10.0.4.99")
    g.add_asset(a, reachable_from_entry=False)
    assert a.id not in g.reachable_assets()
    assert not g.is_reachable(a.id)


def test_services_attached_and_counted() -> None:
    g = AttackGraph()
    a = asset("10.0.4.12", [22, 80, 443])
    g.add_asset(a)
    assert len(g.service_ids(a.id)) == 3
    assert g.stats()["services"] == 3
    assert g.stats()["assets"] == 1


def test_shortest_path_entry_to_service() -> None:
    g = AttackGraph()
    a = asset("10.0.4.12", [80])
    g.add_asset(a)
    svc_id = g.service_ids(a.id)[0]
    path = g.shortest_path(svc_id)
    assert path is not None
    assert path[0] == ENTRY_NODE
    assert path[-1] == svc_id


def test_lateral_pivot_makes_internal_asset_reachable() -> None:
    g = AttackGraph()
    dmz = asset("10.0.4.12", [80])
    internal = asset("10.0.99.5", [3306])
    g.add_asset(dmz)
    g.add_asset(internal, reachable_from_entry=False)
    assert not g.is_reachable(internal.id)
    # A pivot edge from the DMZ host to the internal host opens reachability.
    g.add_edge(dmz.id, internal.id, kind="pivot")
    assert g.is_reachable(internal.id)
    assert internal.id in g.reachable_assets()


def test_add_service_to_unknown_asset_raises() -> None:
    g = AttackGraph()
    with pytest.raises(UnknownNodeError):
        g.add_service("a-nope", Service(port=80))


def test_shortest_path_unknown_endpoint_raises() -> None:
    g = AttackGraph()
    with pytest.raises(UnknownNodeError):
        g.shortest_path("a-missing")


def test_shortest_path_returns_none_when_unreachable() -> None:
    g = AttackGraph()
    a = asset("10.0.4.99")
    g.add_asset(a, reachable_from_entry=False)
    assert g.shortest_path(a.id) is None
