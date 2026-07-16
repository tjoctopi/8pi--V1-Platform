"""Knowledge Store — attack graph, asset inventory, findings (spec §2, §5)."""

from __future__ import annotations

from .dedup import DedupIndex, default_key
from .graph import ENTRY_NODE, AttackGraph, NodeType
from .graph_backend import GraphBackend, build_graph_backend
from .store import KnowledgeStore
from .worldmodel import WorldModel

__all__ = [
    "ENTRY_NODE",
    "AttackGraph",
    "DedupIndex",
    "KnowledgeStore",
    "NodeType",
    "default_key",
    "GraphBackend",
    "build_graph_backend",
    "WorldModel",
]
