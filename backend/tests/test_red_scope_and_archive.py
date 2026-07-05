"""Tests for Red Scope incident hub + engagement archive/unarchive (iteration 6)."""
import os
import pytest
import requests

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


# ---------- Red Scope aggregation ----------
def test_red_scope_feed(s):
    r = s.get(f"{API}/red-scope", timeout=20)
    assert r.status_code == 200, r.text
    j = r.json()
    for k in ("halted_engagements", "critical_findings", "exploit_approvals", "counts"):
        assert k in j
    counts = j["counts"]
    for k in ("halted", "critical_findings", "exploit_approvals"):
        assert k in counts and isinstance(counts[k], int)
    # counts must equal list lengths
    assert counts["halted"] == len(j["halted_engagements"])
    assert counts["critical_findings"] == len(j["critical_findings"])
    assert counts["exploit_approvals"] == len(j["exploit_approvals"])


def test_red_scope_requires_auth():
    r = requests.get(f"{API}/red-scope", timeout=10)
    assert r.status_code == 401


# ---------- Red Scope chat (Adversary Copilot) ----------
def test_red_scope_chat_produces_draft(s):
    r = s.post(f"{API}/red-scope/chat", json={
        "message": "Design an offensive agent to test SQL injection on app.example.com login portal.",
        "history": [],
    }, timeout=90)
    assert r.status_code == 200, r.text
    j = r.json()
    assert "reply" in j
    assert isinstance(j["reply"], str) and len(j["reply"]) > 0
    assert j.get("route") in ("hosted-frontier", "local-openweight")
    # Draft should typically be present for a clear SQLi ask; if the model asked a clarifier,
    # 'draft' may be None. Accept either, but validate shape when present.
    draft = j.get("draft")
    if draft is not None:
        for k in ("name", "role", "max_intensity", "tools", "target", "technique", "rationale"):
            assert k in draft, f"draft missing {k}"
        assert draft["role"] in ("offensive", "defensive", "recon")
        assert draft["max_intensity"] in ("recon", "safe-active", "exploit")
        assert isinstance(draft["tools"], list) and len(draft["tools"]) >= 1


# ---------- Red Scope save-to-registry ----------
def test_red_scope_save_agent_and_persist(s):
    payload = {
        "name": "TEST_redscope_sqli_agent",
        "role": "offensive",
        "max_intensity": "exploit",
        "tools": ["nmap", "sqlmap"],
        "target": "app.example.com",
        "technique": "OWASP A03 Injection",
        "rationale": "chain recon + sqli",
    }
    r = s.post(f"{API}/red-scope/agents", json=payload, timeout=30)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["name"] == "TEST_redscope_sqli_agent"
    assert doc["role"] == "offensive"
    assert doc["origin"] == "red-scope"
    assert set(doc["spec"]["tools"]) == {"nmap", "sqlmap"}
    assert doc["spec"]["guardrails"]["max_intensity"] == "exploit"
    aid = doc["id"]

    # Verify persistence: agent shows up in the registry
    r = s.get(f"{API}/agents", timeout=15)
    assert r.status_code == 200
    agents = r.json()["agents"]
    found = next((a for a in agents if a["id"] == aid), None)
    assert found is not None
    assert found["origin"] == "red-scope"


def test_red_scope_save_sanitizes_bad_input(s):
    """Invalid tool + bogus role/intensity should be sanitized, not 500."""
    r = s.post(f"{API}/red-scope/agents", json={
        "name": "TEST_redscope_sanitize",
        "role": "notarole",
        "max_intensity": "godmode",
        "tools": ["metasploit", "sqlmap"],  # metasploit not allowed
    }, timeout=15)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["role"] == "offensive"  # coerced default
    assert doc["spec"]["guardrails"]["max_intensity"] == "safe-active"  # coerced default
    tools = doc["spec"]["tools"]
    assert "metasploit" not in tools
    assert "sqlmap" in tools


# ---------- Archive / Unarchive engagements ----------
def _make_engagement(s, name):
    r = s.post(f"{API}/engagements", json={"name": name, "estate_seeds": ["10.55.0.0/24"]})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_archive_hides_by_default_and_include_archived_shows_it(s):
    eid = _make_engagement(s, "TEST_archive_flow")

    # Archive
    r = s.post(f"{API}/engagements/{eid}/archive")
    assert r.status_code == 200
    assert r.json()["archived"] is True

    # Default list must NOT contain it
    engs = s.get(f"{API}/engagements").json()["engagements"]
    assert not any(e["id"] == eid for e in engs), "archived engagement leaked into default list"

    # include_archived=1 must contain it, with archived=True
    engs2 = s.get(f"{API}/engagements?include_archived=1").json()["engagements"]
    match = next((e for e in engs2 if e["id"] == eid), None)
    assert match is not None
    assert match["archived"] is True

    # Unarchive
    r = s.post(f"{API}/engagements/{eid}/unarchive")
    assert r.status_code == 200
    assert r.json()["archived"] is False

    # Now appears in default list again
    engs3 = s.get(f"{API}/engagements").json()["engagements"]
    match = next((e for e in engs3 if e["id"] == eid), None)
    assert match is not None
    assert match["archived"] is False


def test_dogfood_still_pinned_and_unarchived(s):
    engs = s.get(f"{API}/engagements").json()["engagements"]
    dog = next((e for e in engs if "Dogfood" in e["name"]), None)
    assert dog is not None, "seeded Dogfood engagement missing from default list"
    assert dog.get("archived") is False


# ---------- Regression: create_agent_core path still works ----------
def test_create_agent_core_via_public_api(s):
    r = s.post(f"{API}/agents", json={
        "name": "TEST_core_refactor_agent",
        "role": "recon",
        "tools": ["nmap"],
        "max_intensity": "recon",
    })
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["name"] == "TEST_core_refactor_agent"
    assert doc["role"] == "recon"
