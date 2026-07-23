"""Pure translators: engine pydantic objects → frontend JSON shapes.

Every function here is side-effect-free and takes an engine schema object,
returning a plain ``dict`` in the exact shape the React console expects (see
``frontend/src/lib/api.js`` and the page/tab components). Keeping the mapping
pure makes it unit-testable without booting an Engine or a web server.

The engine's domain model is richer and differently named than the console's
prototype model, so this is where the vocabularies are reconciled — e.g. the
engine's calibrated ``Finding.priority`` + ``exploit_prob`` become the console's
``severity`` + ``exploitability`` buckets.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..governance.audit import AuditEntry
from ..schemas.findings import (
    VULN_TYPE_PREFIXES,
    Asset,
    Finding,
    FindingState,
    Priority,
    Service,
)

# ── finding vocabulary reconciliation ────────────────────────────────────────

#: engine calibrated priority → console severity chip
_PRIORITY_TO_SEVERITY: dict[str, str] = {
    Priority.PATCH_IMMEDIATELY.value: "crit",
    Priority.HIGH.value: "high",
    Priority.MEDIUM.value: "med",
    Priority.LOW.value: "low",
    Priority.INFORMATIONAL.value: "info",
}

#: engine finding state → console status. The console also has remediating /
#: retest / closed states that are driven by the remediation lifecycle; a bare
#: finding maps to open unless it was rejected (a proven false positive).
_STATE_TO_STATUS: dict[str, str] = {
    FindingState.PROPOSED.value: "open",
    FindingState.VERIFIED.value: "open",
    FindingState.CONFIRMED.value: "open",
    FindingState.REJECTED.value: "false-positive",
}


def _technique_for(finding_type: str) -> str | None:
    """ATT&CK technique id for a finding type, if the catalog knows one."""

    try:
        from ..attack.catalog import technique_for_finding_type

        return technique_for_finding_type(finding_type) or None
    except Exception:  # pragma: no cover - catalog is optional to serialization
        return None


def _source(f: Finding) -> str | None:
    """Which console lane surfaced the finding.

    A finding the Exploitability Matcher produced — a CVE match or an
    oracle-proven vulnerability finalised with impact/remediation — belongs to
    the console's *Vulnerability & Patch Loop* (the version → CVE/KEV →
    exploitable-by-reachability → remediate → re-test view). We recognise those
    by the correlation output they carry (a ``reachability_reason`` and either a
    CVSS or a CVE type), which the matcher stamps on every finding it confirms.
    Everything else keeps its raw emitter for the Findings detail view.
    """

    meta = f.metadata or {}
    ftype = (f.type or "").lower()
    is_correlated_vuln = (
        ftype.startswith("cve-") or ftype.startswith(VULN_TYPE_PREFIXES)
    ) and bool(meta.get("reachability_reason") or meta.get("cvss"))
    if is_correlated_vuln:
        return "vuln-loop"
    return f.proposed_by or meta.get("source")


def _exploitability(f: Finding) -> str:
    """Console's three-state exploitability from the engine's richer signals."""

    if f.state is FindingState.CONFIRMED:
        return "confirmed"
    if f.reachable:
        return "reachable"
    return "unconfirmed"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def finding_to_json(f: Finding) -> dict[str, Any]:
    """Engine :class:`Finding` → console finding row."""

    meta = f.metadata or {}
    cve_refs = meta.get("cve_refs") or meta.get("cves") or []
    if not cve_refs and f.type and f.type.lower().startswith("cve-"):
        cve_refs = [f.type.upper()]
    severity = (
        _PRIORITY_TO_SEVERITY.get(f.priority.value, "info")
        if f.priority is not None
        else "info"
    )
    return {
        "id": f.id,
        "engagement_id": f.engagement_id,
        "asset_id": f.asset,
        "title": f.title or f.type,
        "severity": severity,
        "status": _STATE_TO_STATUS.get(f.state.value, "open"),
        "exploitability": _exploitability(f),
        "exploit_prob": f.exploit_prob,
        "cvss": meta.get("cvss"),
        "cve_refs": list(cve_refs),
        "kev": bool(f.on_kev),
        "technique_ref": _technique_for(f.type),
        "reachability_reason": meta.get("reachability_reason"),
        "source": _source(f),
        "product": meta.get("product"),
        "vulnerable_version": meta.get("vulnerable_version"),
        "patched_version": meta.get("patched_version"),
        "remediation": meta.get("remediation"),
        "evidence_refs": [
            {"type": "audit", "detail": ev, "invocation_id": ev} for ev in f.evidence
        ],
        "created_at": f.created_at,
        "updated_at": f.updated_at,
    }


def service_to_json(s: Service) -> dict[str, Any]:
    """Engine :class:`Service` → console service/version entry."""

    return {
        "port": s.port,
        "protocol": s.protocol,
        "name": s.name,
        "product": s.product,
        "version": s.version,
        "banner": s.banner,
    }


def asset_to_json(a: Asset) -> dict[str, Any]:
    """Engine :class:`Asset` → console asset row.

    The console distinguishes host/webapp/service and carries an
    ``identifiers`` bag; the engine keys everything off ``address`` + a service
    list. We infer a coarse type (webapp when an http service is present) and
    surface versions the way AssetsTab reads them.
    """

    host = a.hostnames[0] if a.hostnames else None
    ip = a.address if _is_ip(a.address) else None
    if host is None and not ip:
        host = a.address  # non-IP address is effectively a hostname

    services = [service_to_json(s) for s in a.services]
    has_web = any((s.name or "").startswith(("http", "https")) for s in a.services)
    versions = [
        {"product": s.product, "version": s.version, "port": s.port}
        for s in a.services
        if s.product or s.version
    ]
    return {
        "id": a.id,
        "engagement_id": a.engagement_id,
        "type": "webapp" if has_web else "host",
        "identifiers": {
            "host": host,
            "ip": ip,
            "url": None,
            "port": None,
            "service": None,
        },
        "exposure": "unknown",
        "reachable": a.reachable,
        "versions": versions,
        "services": services,
        "first_seen": a.first_seen,
        "last_seen": a.first_seen,
    }


# ── audit ─────────────────────────────────────────────────────────────────────

def _actor_role(action: str, actor: str) -> str:
    """Coarse actor lane the console colours + filters by.

    The engine stores a single ``actor`` identity string (an operator email, an
    approver id, the internal service principal, or an agent name). The console
    buckets these into four lanes; we derive the lane from the action namespace,
    keeping the identity separately as ``actor_id``.
    """

    if action.startswith(("tool.", "agent.", "campaign.", "model.")):
        return "agent"
    if action.startswith("approval.") or "approver" in actor.lower():
        return "approver"
    if action.startswith(("engagement.", "roe.", "finding.")):
        return "operator"
    return "system"


def audit_entry_to_json(e: AuditEntry) -> dict[str, Any]:
    """Engine hash-chained :class:`AuditEntry` → console audit event.

    The console's tamper-evident audit view expects ``event_type``/``hash``;
    the engine names these ``action``/``entry_hash``. The chain fields
    (``seq``/``prev_hash``/``hash``) map one-to-one so the console's
    verify-chain view reflects the *real* chain. ``actor`` is the coarse lane
    (operator/agent/approver/system) the UI colours by; ``actor_id`` is the
    real identity string.
    """

    return {
        "id": e.entry_hash,
        "seq": e.seq,
        "ts": e.ts,
        "actor": _actor_role(e.action, e.actor),
        "actor_id": e.actor,
        "engagement_id": e.engagement_id,
        "event_type": e.action,
        "target": e.target,
        "payload": e.payload,
        "prev_hash": e.prev_hash,
        "hash": e.entry_hash,
    }
