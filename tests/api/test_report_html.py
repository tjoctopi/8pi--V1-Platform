"""Report HTML renderer (Slice 6) — pure, self-contained document."""

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
         "exploitability": "confirmed", "exploit_prob": 0.99,
         "cve_refs": ["CVE-2020-0001"], "kev": True},
    ],
}


def test_render_report_html_is_self_contained_and_escaped() -> None:
    html = render_report_html(_REPORT)
    assert html.startswith("<!doctype html>")
    assert "Acme &lt;Q3&gt;" in html          # engagement name HTML-escaped
    assert "RCE on /dns" in html
    assert "CVE-2020-0001" in html
    assert "CHAIN VERIFIED" in html
    assert "http://" not in html               # no external asset references
    assert "https://" not in html


def test_render_report_html_handles_empty_findings() -> None:
    empty = {**_REPORT, "findings": []}
    html = render_report_html(empty)
    assert "No findings recorded." in html


def test_render_report_html_shows_broken_chain() -> None:
    broken = {**_REPORT, "summary": {**_REPORT["summary"], "audit_chain_valid": False}}
    assert "CHAIN BROKEN" in render_report_html(broken)
