"""Shared data-access helpers (leaf module, depends only on db)."""
import uuid
from datetime import datetime, timezone, timedelta
from db import db


def gen_id(prefix=""):
    return (prefix + uuid.uuid4().hex) if prefix else uuid.uuid4().hex


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def iso_in(days=0, hours=0):
    return (datetime.now(timezone.utc) + timedelta(days=days, hours=hours)).isoformat()


def doc_out(doc):
    """Map Mongo _id -> id for JSON responses."""
    if doc is None:
        return None
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = doc.pop("_id")
    return doc


def docs_out(docs):
    return [doc_out(d) for d in docs]


async def get_engagement(eid):
    return await db.engagements.find_one({"_id": eid})


async def get_roe_by_id(rid):
    if not rid:
        return None
    return await db.roes.find_one({"_id": rid})


async def get_roe(engagement):
    if not engagement:
        return None
    return await get_roe_by_id(engagement.get("roe_id"))
