"""Report HTML renderer — pure, self-contained, client-ready document."""

from __future__ import annotations

from attack_engine.api.report_html import render_report_html

_REPORT = {
    "generated_at": "2026-07-18T00:00:00Z",
    "engagement": {"id": "eng-x", "name": "Acme <Q3>", "status": "active"},
    "roe": {"max_intensity": "exploit", "signed_by": "ciso@acme.example"},
    "summary": {
        "assets": 3, "findings_total": 2, "audit_events": 12,
        "audit_chain_valid": True, "findings_open_by_severity": {"crit": 1, "high": 1},
    },
    "findings": [
        {"title": "RCE on /dns", "severity": "crit", "asset_id": "10.5.0.12",
         "type": "command-injection", "exploitability": "confirmed", "exploit_prob": 0.99,
         "cvss": 9.8, "cve_refs": ["CVE-2020-0001"], "kev": True,
         "remediation": "Never pass user input to a shell.",
         "reachability_reason": "Proven reachable by a live probe."},
    ],
    "breach": {},
    "footholds": [],
}


def test_render_report_html_is_self_contained_and_escaped() -> None:
    html = render_report_html(_REPORT)
    assert html.startswith("<!doctype html>")
    assert "Acme &lt;Q3&gt;" in html          # engagement name HTML-escaped
    assert "http://" not in html               # no external asset references
    assert "https://" not in html


def test_render_report_html_is_client_readable() -> None:
    # The professional, non-technical sections a client report must carry.
    html = render_report_html(_REPORT)
    for section in ("Executive Summary", "Risk at a Glance", "Proof of Compromise",
                    "Key Findings", "Methodology", "Assurance"):
        assert section in html, section
    # a crit + confirmed finding drives the CRITICAL verdict + a plain-language card
    assert "CRITICAL RISK" in html
    assert "RCE on /dns" in html and "CVE-2020-0001" in html
    assert "What this means" in html and "How to fix it" in html
    assert "verified" in html                  # audit-chain assurance


def test_render_report_html_proof_of_compromise_from_foothold() -> None:
    # A live foothold surfaces the proof-of-compromise section with real evidence.
    rep = {
        **_REPORT,
        "breach": {"live_footholds": 1, "domain_admin": False, "crown_reached": 1},
        "footholds": [{
            "id": "s1", "host": "10.5.0.12", "status": "active",
            "proof": {"whoami": "www-data", "hostname": "box"},
            "loot": [{"command": "id", "output": "uid=33(www-data)"}],
            "site_content": {"url": "http://10.5.0.12/", "status": 200,
                             "snippet": "Metasploitable2 - Linux"},
        }],
    }
    html = render_report_html(rep)
    assert "Interactive access gained" in html
    assert "www-data" in html and "10.5.0.12" in html
    assert "Metasploitable2 - Linux" in html   # captured live content shown
    assert "uid=33(www-data)" in html          # loot command output shown


def test_render_report_html_handles_empty_findings() -> None:
    empty = {**_REPORT, "findings": [],
             "summary": {**_REPORT["summary"], "findings_open_by_severity": {}}}
    html = render_report_html(empty)
    assert "All Findings (0)" in html
    assert "No live foothold was established" in html


def test_render_report_html_shows_broken_chain() -> None:
    broken = {**_REPORT, "summary": {**_REPORT["summary"], "audit_chain_valid": False}}
    assert "BROKEN" in render_report_html(broken)
