"""SEC-04 tamper-evident, append-only, hash-chained audit log (DM-07)."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from db import db

SYSTEM = "__system__"


def _canonical(payload):
    return json.dumps(payload or {}, sort_keys=True, default=str)


def _compute_hash(prev_hash, seq, ts, actor, actor_id, eid, event_type, payload):
    material = f"{prev_hash}|{seq}|{ts}|{actor}|{actor_id}|{eid}|{event_type}|{_canonical(payload)}"
    return hashlib.sha256(material.encode()).hexdigest()


async def audit_event(engagement_id, actor, actor_id, event_type, payload=None):
    """Append a hash-chained audit event. Synchronous with the audited action (NFR-AUD-01)."""
    eid = engagement_id or SYSTEM
    last = await db.audit_events.find_one({"engagement_id": eid}, sort=[("seq", -1)])
    prev_hash = last["hash"] if last else "GENESIS"
    seq = (last["seq"] + 1) if last else 0
    ts = datetime.now(timezone.utc).isoformat()
    h = _compute_hash(prev_hash, seq, ts, actor, actor_id, eid, event_type, payload)
    doc = {
        "_id": uuid.uuid4().hex,
        "seq": seq,
        "ts": ts,
        "actor": actor,
        "actor_id": actor_id,
        "engagement_id": eid,
        "event_type": event_type,
        "payload": payload or {},
        "prev_hash": prev_hash,
        "hash": h,
    }
    await db.audit_events.insert_one(doc)
    return doc


async def verify_chain(engagement_id):
    eid = engagement_id or SYSTEM
    events = await db.audit_events.find({"engagement_id": eid}).sort("seq", 1).to_list(100000)
    prev = "GENESIS"
    for e in events:
        h = _compute_hash(prev, e["seq"], e["ts"], e["actor"], e["actor_id"], eid, e["event_type"], e["payload"])
        if h != e["hash"] or e["prev_hash"] != prev:
            return {"valid": False, "broken_at_seq": e["seq"], "count": len(events)}
        prev = e["hash"]
    return {"valid": True, "count": len(events), "head_hash": prev if events else "GENESIS"}
