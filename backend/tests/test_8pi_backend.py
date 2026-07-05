"""Backend tests for 8pi Platform v1 covering all major flows."""
import os
import time
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
API = f"{BASE}/api"

ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@8pi.io")
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "8pi-admin-changeme")


@pytest.fixture(scope="module")
def s():
    """Authenticated requests session — logs in as the seeded admin and attaches the Bearer token."""
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    r = sess.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    token = r.json().get("access_token")
    assert token
    sess.headers["Authorization"] = f"Bearer {token}"
    return sess


@pytest.fixture(scope="module")
def unauth():
    """Bare session (no Bearer) — used to test that /api routes actually require auth."""
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    return sess


@pytest.fixture(scope="module")
def engagements(s):
    r = s.get(f"{API}/engagements", timeout=30)
    assert r.status_code == 200
    return r.json()["engagements"]


@pytest.fixture(scope="module")
def dogfood(engagements):
    e = next((x for x in engagements if "Dogfood" in x["name"]), None)
    assert e, "seeded Dogfood engagement not found"
    return e


@pytest.fixture(scope="module")
def acme_draft(engagements):
    e = next((x for x in engagements if x["status"] == "draft" and not x["roe_signed"]), None)
    assert e, "no draft engagement found"
    return e


# --- Health & stats ---
def test_health(s):
    r = s.get(f"{API}/", timeout=15)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_auth_required(unauth):
    """Every /api route MUST require a Bearer token except the small public whitelist."""
    for path in ("/engagements", "/agents", "/tools", "/model/routes", "/stats"):
        r = unauth.get(f"{API}{path}", timeout=10)
        assert r.status_code == 401, f"{path} should be protected — got {r.status_code}"
    # public endpoints stay open
    for path in ("/", "/health", "/readiness"):
        r = unauth.get(f"{API}{path}", timeout=10)
        assert r.status_code == 200, f"{path} should be public — got {r.status_code}"


def test_auth_bad_password_locks_out(unauth):
    """Repeated wrong passwords → 429 lockout for that (IP, email) pair."""
    for _ in range(6):
        unauth.post(f"{API}/auth/login", json={"email": "nobody@8pi.io", "password": "wrong"}, timeout=10)
    r = unauth.post(f"{API}/auth/login", json={"email": "nobody@8pi.io", "password": "wrong"}, timeout=10)
    assert r.status_code in (401, 429), r.status_code


def test_health_endpoint(s):
    t0 = time.time()
    r = s.get(f"{API}/health", timeout=5)
    dt = (time.time() - t0) * 1000
    assert r.status_code == 200
    j = r.json()
    assert j == {"status": "ok", "platform": "8pi", "version": "v1"}
    assert dt < 500, f"health took {dt:.0f}ms"


def test_readiness_endpoint(s):
    t0 = time.time()
    r = s.get(f"{API}/readiness", timeout=5)
    dt = (time.time() - t0) * 1000
    assert r.status_code == 200
    j = r.json()
    assert j.get("mongo") == "up"
    assert dt < 500, f"readiness took {dt:.0f}ms"


def test_attack_path_endpoint(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/attack-path", timeout=30)
    assert r.status_code == 200
    j = r.json()
    for k in ("paths", "points", "arcs", "entry_points", "crown_jewels", "stats"):
        assert k in j, f"missing key {k}"
    assert len(j["paths"]) > 0
    assert j["stats"]["paths"] >= 1


LAYER_ORDER = ["endpoint", "saas", "cloud", "dev", "code", "onprem", "edge"]


def test_attack_path_ecosystem_payload(s, dogfood):
    """New ecosystem-globe payload: continents, layer_stats, layer fields on points/paths/steps."""
    eid = dogfood["id"]
    j = s.get(f"{API}/engagements/{eid}/attack-path", timeout=30).json()

    # continents: 7 GeoJSON polygons in LAYER_ORDER
    assert "continents" in j and len(j["continents"]) == 7
    keys = [c["key"] for c in j["continents"]]
    assert keys == LAYER_ORDER
    for c in j["continents"]:
        assert c["geometry"]["type"] == "Polygon"
        assert isinstance(c["geometry"]["coordinates"], list) and len(c["geometry"]["coordinates"][0]) >= 4
        for f in ("key", "label", "sub", "color", "center"):
            assert f in c

    # layer_stats: 7 entries, each with count >= 1 (dogfood seed enrichment)
    assert "layer_stats" in j and len(j["layer_stats"]) == 7
    for st in j["layer_stats"]:
        assert st["key"] in LAYER_ORDER
        assert st["count"] >= 1, f"layer {st['key']} has count 0 — seed enrichment missing"
        assert st["top"] is not None

    # points: layer + layer_label + color
    for p in j["points"][:20]:
        assert p["layer"] in LAYER_ORDER
        assert p["layer_label"]
        assert p["color"].startswith("#")

    # paths: layers_traversed + steps carry layer fields
    for p in j["paths"]:
        assert isinstance(p["layers_traversed"], list) and len(p["layers_traversed"]) == len(p["steps"])
        for step in p["steps"]:
            assert step["layer"] in LAYER_ORDER
            assert step["layer_label"]
            assert step["layer_color"].startswith("#")


def test_attack_path_stream_mentions_layer(s, dogfood):
    """SSE stream must reference at least one ecosystem layer name and end with hosted-frontier done."""
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/attack-path/stream", timeout=120, stream=True)
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("content-type", "")
    layer_names = ("Endpoint", "SaaS", "Cloud", "Dev", "Code", "On-Prem", "Edge")
    collected = ""
    saw_done = False
    for line in r.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data:"):
            continue
        collected += line
        if '"done": true' in line or '"done":true' in line:
            saw_done = True
            assert '"hosted-frontier"' in line or '"local-openweight"' in line
            break
    r.close()
    assert saw_done
    assert any(name in collected for name in layer_names), "no ecosystem layer name in stream body"


def test_attack_path_stream(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/attack-path/stream", timeout=90, stream=True)
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("content-type", "")
    saw_done = False
    saw_data = False
    for line in r.iter_lines(decode_unicode=True):
        if not line:
            continue
        if line.startswith("data:"):
            saw_data = True
            if '"done": true' in line or '"done":true' in line:
                saw_done = True
                assert "hosted-frontier" in line
                break
    r.close()
    assert saw_data and saw_done


def test_stats(s):
    r = s.get(f"{API}/stats", timeout=15)
    assert r.status_code == 200
    d = r.json()
    for k in ("engagements", "assets", "findings_open", "tool_invocations", "pending_approvals", "agents"):
        assert k in d


# --- Engagement lifecycle: activate rejected before sign, sign immutable, activate succeeds ---
def test_engagement_lifecycle(s):
    r = s.post(f"{API}/engagements", json={"name": "TEST_lifecycle", "estate_seeds": ["10.99.0.0/24"]})
    assert r.status_code == 200
    eng = r.json()
    eid = eng["id"]
    assert eng["status"] == "draft"

    # cannot activate before signing
    r = s.post(f"{API}/engagements/{eid}/activate")
    assert r.status_code == 412

    # update RoE
    r = s.put(f"{API}/engagements/{eid}/roe", json={
        "scope_allowlist": ["10.99.0.0/24"], "scope_denylist": [],
        "allowed_tools": ["nmap"], "allowed_techniques": [],
        "max_intensity": "recon"
    })
    assert r.status_code == 200

    # sign
    r = s.post(f"{API}/engagements/{eid}/roe/sign", json={"signed_by": "test@ci"})
    assert r.status_code == 200
    assert r.json()["signature"]

    # second sign must be 409
    r = s.post(f"{API}/engagements/{eid}/roe/sign", json={"signed_by": "again"})
    assert r.status_code == 409

    # PUT after signing must be rejected
    r = s.put(f"{API}/engagements/{eid}/roe", json={
        "scope_allowlist": ["1.1.1.1"], "scope_denylist": [], "allowed_tools": ["nmap"],
        "allowed_techniques": [], "max_intensity": "recon"
    })
    assert r.status_code == 409

    # activate succeeds
    r = s.post(f"{API}/engagements/{eid}/activate")
    assert r.status_code == 200
    assert r.json()["status"] == "active"


# --- Audit chain ---
def test_audit_chain(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/audit")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) > 0

    r = s.get(f"{API}/engagements/{eid}/audit/verify")
    assert r.status_code == 200
    v = r.json()
    assert v.get("valid") is True
    assert v.get("count", 0) > 0


# --- Tool scope enforcement (SEC-02, FR-TOOL-07) ---
def test_tool_scope_in_and_out(s, dogfood):
    eid = dogfood["id"]
    # Get an in-scope target from RoE
    detail = s.get(f"{API}/engagements/{eid}").json()
    allow = detail["roe"]["scope_allowlist"]
    # Find a hostname-like target
    target = next((t for t in allow if "8pi.internal" in t or "app" in t), allow[0])

    r = s.post(f"{API}/tools/nmap/run", json={
        "engagement_id": eid, "target": target, "intensity": "recon"
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "completed"

    # out of scope
    r = s.post(f"{API}/tools/nmap/run", json={
        "engagement_id": eid, "target": "8.8.8.8", "intensity": "recon"
    })
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "refused"
    assert j["scope_check_result"]["reason"] == "target_out_of_scope"


def test_licensed_tools_451(s, dogfood):
    for tool in ("burp", "nessus"):
        r = s.post(f"{API}/tools/{tool}/run", json={
            "engagement_id": dogfood["id"], "target": "app.dogfood.8pi.internal"
        })
        assert r.status_code == 451, f"{tool}: {r.status_code}"


# --- Model Gateway ---
def test_model_routes(s):
    r = s.get(f"{API}/model/routes")
    assert r.status_code == 200
    routes = r.json()["routes"]
    assert len(routes) == 3


def test_model_infer_hosted(s):
    r = s.post(f"{API}/model/infer", json={
        "purpose": "test", "task_class": "reason", "sensitivity": "internal",
        "messages": [{"role": "user", "content": "Reply with a single word: OK"}],
        "max_tokens": 32
    }, timeout=60)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["route"] == "hosted-frontier"
    assert isinstance(j["text"], str) and len(j["text"]) > 0


def test_model_infer_sensitive_pinned_local(s):
    r = s.post(f"{API}/model/infer", json={
        "purpose": "test", "task_class": "reason", "sensitivity": "sensitive",
        "messages": [{"role": "user", "content": "email me at foo@bar.com password=hunter2"}]
    }, timeout=30)
    assert r.status_code == 200
    j = r.json()
    assert j["route"] != "hosted-frontier"
    assert j["route"] == "local-openweight"
    assert j["redaction_applied"] is True


def test_model_openmythos_501(s):
    r = s.post(f"{API}/model/infer", json={
        "purpose": "t", "task_class": "reason", "sensitivity": "internal",
        "route": "openmythos-7b", "messages": [{"role": "user", "content": "hi"}]
    })
    assert r.status_code == 501


def test_model_calls_list(s):
    r = s.get(f"{API}/model/calls")
    assert r.status_code == 200
    assert "calls" in r.json()


# --- Sensing / Threat map / Findings ---
def test_sensing_and_threat(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/assets")
    assert r.status_code == 200
    assert len(r.json().get("assets", [])) > 0

    r = s.get(f"{API}/engagements/{eid}/threat-map")
    assert r.status_code == 200
    tm = r.json()
    assert "nodes" in tm and "edges" in tm


def test_vuln_scan_and_findings(s, dogfood):
    eid = dogfood["id"]
    r = s.post(f"{API}/engagements/{eid}/vuln-scan")
    assert r.status_code == 200

    r = s.get(f"{API}/engagements/{eid}/findings")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert len(findings) > 0
    f = findings[0]
    for k in ("severity", "exploitability", "remediation"):
        assert k in f


def test_vuln_loop_close(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/findings")
    findings = r.json()["findings"]
    open_f = next((f for f in findings if f.get("status") == "open"), None)
    if not open_f:
        pytest.skip("no open finding")
    fid = open_f["id"]
    r = s.post(f"{API}/findings/{fid}/remediate", json={"note": "TEST_patched"})
    assert r.status_code == 200
    r = s.post(f"{API}/findings/{fid}/retest")
    assert r.status_code == 200
    assert r.json().get("status") == "closed"


# --- Agents & Sandbox / Promote ---
def test_agents_list(s):
    r = s.get(f"{API}/agents")
    assert r.status_code == 200
    agents = r.json()["agents"]
    assert len(agents) >= 3
    roles = {a["role"] for a in agents}
    assert "offensive" in roles


def test_dev_agent_cannot_run(s, dogfood):
    agents = s.get(f"{API}/agents").json()["agents"]
    dev = next((a for a in agents if a.get("promotion_state") == "dev"), None)
    if not dev:
        pytest.skip("no dev agent")
    r = s.post(f"{API}/engagements/{dogfood['id']}/agents/{dev['id']}/run")
    assert r.status_code == 412


def test_promote_requires_sandbox_pass(s):
    # create new dev agent
    r = s.post(f"{API}/agents", json={
        "name": "TEST_agent", "role": "offensive", "tools": ["nmap"], "max_intensity": "recon"
    })
    assert r.status_code == 200
    aid = r.json()["id"]

    # promote to authorized without sandbox pass -> 412
    r = s.post(f"{API}/agents/{aid}/promote", json={"to_state": "authorized"})
    assert r.status_code == 412

    # sandbox run
    r = s.post(f"{API}/agents/{aid}/sandbox-run")
    assert r.status_code == 200
    assert r.json()["passed"] is True

    # now promote
    r = s.post(f"{API}/agents/{aid}/promote", json={"to_state": "authorized"})
    assert r.status_code == 200
    assert r.json()["promotion_state"] == "authorized"


# --- Offensive agent run + approval flow ---
def test_offensive_run_and_approval(s, dogfood):
    eid = dogfood["id"]
    agents = s.get(f"{API}/agents").json()["agents"]
    off = next((a for a in agents if a["role"] == "offensive" and a["promotion_state"] == "authorized"), None)
    assert off, "no authorized offensive agent"
    r = s.post(f"{API}/engagements/{eid}/agents/{off['id']}/run", timeout=90)
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["status"] == "completed"

    # Approve as admin (role hierarchy: admin > approver — allowed)
    pend = s.get(f"{API}/engagements/{eid}/approvals?status=pending").json()["approvals"]
    if pend:
        aid = pend[0]["id"]
        r = s.post(f"{API}/approvals/{aid}/approve", json={})
        assert r.status_code == 200
        assert r.json()["status"] == "approved"


def test_approve_rbac_forbidden_for_operator(s, unauth):
    """A user with role=operator must get 403 when trying to approve or list users.
    The role check runs BEFORE the approval-existence lookup, so we can test with a fake id."""
    # 1. Ensure operator account exists
    r = s.post(f"{API}/auth/users", json={
        "email": "test.operator@8pi.io", "password": "opoperator123", "name": "op", "role": "operator"
    })
    assert r.status_code in (200, 409)

    # 2. Login as the operator
    login = unauth.post(f"{API}/auth/login", json={
        "email": "test.operator@8pi.io", "password": "opoperator123"
    }, timeout=10)
    assert login.status_code == 200
    tok = login.json()["access_token"]
    op = requests.Session()
    op.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {tok}"})

    # 3. Operator must get 403 on approve, deny (role check runs before approval lookup),
    # AND on admin-only /auth/users list.
    r = op.post(f"{API}/approvals/nonexistent/approve", json={})
    assert r.status_code == 403, f"approve should reject operator — got {r.status_code}: {r.text}"
    r = op.post(f"{API}/approvals/nonexistent/deny", json={})
    assert r.status_code == 403, f"deny should reject operator — got {r.status_code}: {r.text}"
    r = op.get(f"{API}/auth/users")
    assert r.status_code == 403, f"/auth/users should reject operator — got {r.status_code}: {r.text}"


# --- Kill switch ---
def test_kill_switch(s):
    # create fresh engagement so we don't disturb dogfood
    r = s.post(f"{API}/engagements", json={"name": "TEST_kill", "estate_seeds": ["10.77.0.0/24"]})
    eng = r.json()
    eid = eng["id"]
    s.put(f"{API}/engagements/{eid}/roe", json={
        "scope_allowlist": ["10.77.0.0/24"], "scope_denylist": [], "allowed_tools": ["nmap"],
        "allowed_techniques": [], "max_intensity": "recon"
    })
    s.post(f"{API}/engagements/{eid}/roe/sign", json={"signed_by": "ci"})
    s.post(f"{API}/engagements/{eid}/activate")

    r = s.post(f"{API}/engagements/{eid}/halt")
    assert r.status_code == 200
    assert r.json()["halted"] is True

    # tool run must 423
    r = s.post(f"{API}/tools/nmap/run", json={"engagement_id": eid, "target": "10.77.0.5"})
    assert r.status_code == 423

    r = s.post(f"{API}/engagements/{eid}/resume")
    assert r.status_code == 200


# --- Reporting ---
def test_reports(s, dogfood):
    eid = dogfood["id"]
    r = s.get(f"{API}/engagements/{eid}/report")
    assert r.status_code == 200
    j = r.json()
    for k in ("summary", "findings", "risk_map", "audit"):
        assert k in j

    r = s.get(f"{API}/engagements/{eid}/report.html")
    assert r.status_code == 200
    assert "html" in r.headers.get("content-type", "").lower() or "<html" in r.text.lower()

    r = s.get(f"{API}/engagements/{eid}/report.pdf")
    assert r.status_code == 200
    assert "pdf" in r.headers.get("content-type", "").lower()
