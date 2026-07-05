"""Iteration 7 regression: model_gateway datetime import fix + egress guard + route selection."""
import os
import pytest
import requests
from datetime import datetime

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
API = f"{BASE}/api"
ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@8pi.io")
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "8pi-admin-changeme")


@pytest.fixture(scope="module")
def s():
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    r = sess.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, r.text
    sess.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return sess


def test_auth_required_on_protected(s):
    # regression: bearer token requirement stays intact
    r = requests.get(f"{API}/model/calls?limit=1", timeout=10)
    assert r.status_code in (401, 403)


def test_infer_reason_routes_hosted(s):
    payload = {
        "purpose": "regression_test",
        "task_class": "reason",
        "sensitivity": "internal",
        "messages": [{"role": "user", "content": "Say hello in 3 words."}],
        "max_tokens": 64,
    }
    r = s.post(f"{API}/model/infer", json=payload, timeout=60)
    assert r.status_code == 200, r.text
    j = r.json()
    assert isinstance(j.get("text"), str) and len(j["text"]) > 0
    # reason routes to hosted-frontier by default (may fall back to local-openweight if hosted unavailable)
    assert j.get("route") in ("hosted-frontier", "local-openweight")


def test_infer_sensitive_pinned_local(s):
    payload = {
        "purpose": "sensitive_regression",
        "task_class": "reason",
        "sensitivity": "sensitive",
        "messages": [{"role": "user", "content": "classified internal note"}],
        "max_tokens": 32,
    }
    r = s.post(f"{API}/model/infer", json=payload, timeout=60)
    assert r.status_code == 200, r.text
    j = r.json()
    # SEC-05: sensitive must stay on local-openweight
    assert j.get("route") == "local-openweight", j


def test_calls_records_iso_ts(s):
    # First trigger a call
    s.post(f"{API}/model/infer", json={
        "purpose": "ts_probe", "task_class": "summarize", "sensitivity": "internal",
        "messages": [{"role": "user", "content": "ping"}], "max_tokens": 16,
    }, timeout=60)
    r = s.get(f"{API}/model/calls?limit=1", timeout=15)
    assert r.status_code == 200, r.text
    calls = r.json().get("calls", [])
    assert len(calls) >= 1
    ts = calls[0].get("ts")
    assert isinstance(ts, str) and len(ts) > 0, f"ts missing/invalid: {ts}"
    # Must parse as ISO 8601 (regression: verifies the `from datetime import datetime, timezone` fix)
    parsed = datetime.fromisoformat(ts)
    assert parsed.year >= 2025


def test_routes_endpoint(s):
    r = s.get(f"{API}/model/routes", timeout=10)
    assert r.status_code == 200
    routes = r.json().get("routes", [])
    ids = {rt["id"] for rt in routes}
    assert {"hosted-frontier", "local-openweight", "openmythos-7b"} <= ids
