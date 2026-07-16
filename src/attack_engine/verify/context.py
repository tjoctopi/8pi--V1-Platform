"""Context handed to verification oracles.

Deliberately narrow: an oracle gets a scope-enforcing Tool Runner (its only way
to touch a target), the knowledge store (read-only use), and the audit log. It
never gets a raw socket or the model gateway — verification is *deterministic*
(rule #1), so it must not consult an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..governance.audit import AuditLog
from ..knowledge.store import KnowledgeStore
from ..toolrunner.runner import ToolRunner
from .oob import OobServer


@dataclass
class VerifyContext:
    engagement_id: str
    tool_runner: ToolRunner
    store: KnowledgeStore
    audit: AuditLog
    #: The C2 reverse-shell listener LHOST (O3), if one is stood up. Exploit
    #: modules that use a reverse payload fall back to this when a finding has no
    #: explicit LHOST — so autonomous reverse-shell exploitation has a callback.
    listener_lhost: str | None = None
    #: Out-of-band interaction server for proving *blind* vulnerabilities
    #: (SSRF/XXE/blind-SQLi callbacks). Absent when no listener is stood up; the
    #: OOB oracles then decline to confirm rather than guess (rule #1).
    oob: OobServer | None = None
