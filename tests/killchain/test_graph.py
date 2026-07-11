"""Privilege-graph (attacker's brain) pathfinding tests."""

from __future__ import annotations

from attack_engine.killchain.graph import ENTRY, ExploitEdge, PrivilegeGraph


def _edge(src, dst, cost=1.0, tech="T1", name="x", fid=None):
    return ExploitEdge(src=src, dst=dst, technique=tech, name=name, cost=cost, finding_id=fid)


def test_cheapest_path_finds_route() -> None:
    g = PrivilegeGraph()
    g.add_exploit(_edge(ENTRY, ("h1", "user")))
    g.add_exploit(_edge(("h1", "user"), ("h1", "root"), cost=2))
    g.set_goal("h1", "root")
    chain = g.cheapest_path()
    assert chain is not None
    assert [e.dst for e in chain] == [("h1", "user"), ("h1", "root")]


def test_prefers_cheaper_route() -> None:
    g = PrivilegeGraph()
    g.add_exploit(_edge(ENTRY, ("h1", "user")))
    # Two ways to root: direct (cost 10) vs via a cheap intermediate (1+1).
    g.add_exploit(_edge(("h1", "user"), ("h1", "root"), cost=10))
    g.add_exploit(_edge(("h1", "user"), ("h1", "svc"), cost=1))
    g.add_exploit(_edge(("h1", "svc"), ("h1", "root"), cost=1))
    g.set_goal("h1", "root")
    chain = g.cheapest_path()
    # Route via the cheap intermediate (entry→user→svc→root, cost 3) beats the
    # direct user→root edge (cost 10).
    assert [e.dst for e in chain] == [("h1", "user"), ("h1", "svc"), ("h1", "root")]


def test_no_goal_returns_none() -> None:
    g = PrivilegeGraph()
    g.add_exploit(_edge(ENTRY, ("h1", "user")))
    assert g.cheapest_path() is None


def test_unreachable_goal_returns_none() -> None:
    g = PrivilegeGraph()
    g.add_exploit(_edge(ENTRY, ("h1", "user")))
    g.set_goal("h2", "root")  # island — no edges lead there
    assert g.cheapest_path() is None


def test_start_equals_goal_is_empty_chain() -> None:
    g = PrivilegeGraph()
    g.set_goal(*ENTRY)
    assert g.cheapest_path() == []


def test_stats() -> None:
    g = PrivilegeGraph()
    g.add_exploit(_edge(ENTRY, ("h1", "user")))
    g.add_exploit(_edge(("h1", "user"), ("h1", "root")))
    s = g.stats()
    assert s["exploit_edges"] == 2
    assert s["positions"] >= 3
