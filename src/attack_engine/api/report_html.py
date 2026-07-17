# ruff: noqa: E501  (HTML template lines are intentionally long)
"""Render an engagement report (the ``/report`` JSON) to a standalone HTML page.

Pure and dependency-free: takes the exact dict the ``/engagements/{eid}/report``
endpoint returns and produces a self-contained, printable HTML document (inline
CSS, no external assets). The same HTML is what the PDF export rasterises, so the
two exports never drift.
"""

from __future__ import annotations

from html import escape
from typing import Any

_SEV_COLOR = {
    "crit": "#FF2A6D", "high": "#FF7A00", "med": "#FFC400",
    "low": "#3DD68C", "info": "#7A7A7A",
}


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev, "#7A7A7A")
    return (
        f'<span style="background:{color};color:#000;padding:1px 8px;'
        f'border-radius:3px;font-size:11px;font-weight:700;text-transform:uppercase">'
        f"{escape(sev)}</span>"
    )


def _findings_rows(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="5" class="empty">No findings recorded.</td></tr>'
    rows: list[str] = []
    for f in findings:
        cves = ", ".join(f.get("cve_refs") or []) or "—"
        kev = " · KEV" if f.get("kev") else ""
        prob = f.get("exploit_prob")
        prob_s = f"{prob:.2f}" if isinstance(prob, int | float) else "—"
        cells = [
            _sev_badge(f.get("severity", "info")),
            escape(str(f.get("title") or "")),
            f'<span class="mono">{escape(str(f.get("asset_id") or ""))}</span>',
            f'<span class="mono">{escape(str(f.get("exploitability") or ""))} ({prob_s})</span>',
            f'<span class="mono small">{escape(cves)}{kev}</span>',
        ]
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    return "".join(rows)


def _kv(label: str, value: Any) -> str:
    return (
        f'<div style="margin:4px 0"><span style="color:#7A7A7A;font-size:12px;'
        f'text-transform:uppercase;letter-spacing:.05em">{escape(label)}</span> '
        f'<span style="font-family:monospace;color:#e8e8e8">{escape(str(value))}</span></div>'
    )


def render_report_html(report: dict[str, Any]) -> str:
    """Build a printable HTML document from the report JSON."""

    eng = report.get("engagement", {})
    roe = report.get("roe", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    by_sev = summary.get("findings_open_by_severity", {}) or {}

    name = escape(str(eng.get("name") or "Engagement"))
    generated = escape(str(report.get("generated_at") or ""))
    chain_ok = summary.get("audit_chain_valid", True)
    chain_badge = (
        '<span style="color:#3DD68C">✓ CHAIN VERIFIED</span>'
        if chain_ok else '<span style="color:#FF2A6D">✗ CHAIN BROKEN</span>'
    )
    sev_summary = " · ".join(
        f"{escape(k)}: {escape(str(v))}" for k, v in by_sev.items()
    ) or "none"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>8π Report — {name}</title>
<style>
  @media print {{ body {{ background:#fff; color:#000 }} }}
  body {{ background:#0a0a0a; color:#e8e8e8; font-family:-apple-system,Segoe UI,Roboto,sans-serif;
         margin:0; padding:40px; max-width:1000px; margin:0 auto }}
  h1 {{ font-size:28px; margin:0 0 4px; letter-spacing:-.02em }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.08em; color:#7A7A7A;
        border-bottom:1px solid #222; padding-bottom:6px; margin:32px 0 12px }}
  table {{ width:100%; border-collapse:collapse; font-size:13px }}
  th {{ text-align:left; padding:8px; color:#7A7A7A; font-size:11px; text-transform:uppercase;
        border-bottom:1px solid #333 }}
  td {{ padding:8px; border-bottom:1px solid #222 }}
  .mono {{ font-family:monospace; color:#9fb8a8 }}
  .small {{ font-size:12px }}
  .empty {{ padding:16px; text-align:center; color:#7A7A7A }}
  .card {{ background:#141414; border:1px solid #222; border-radius:6px; padding:16px; margin:8px 0 }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px }}
</style></head>
<body>
  <h1>{name}</h1>
  <div style="color:#7A7A7A;font-size:13px">8π Offensive Engagement Report · generated {generated} · {chain_badge}</div>

  <h2>Engagement</h2>
  <div class="grid">
    <div class="card">
      {_kv("Status", eng.get("status"))}
      {_kv("Engagement ID", eng.get("id"))}
      {_kv("Max intensity", roe.get("max_intensity"))}
      {_kv("RoE signed by", roe.get("signed_by") or "—")}
    </div>
    <div class="card">
      {_kv("Assets", summary.get("assets", 0))}
      {_kv("Findings (total)", summary.get("findings_total", 0))}
      {_kv("Open by severity", sev_summary)}
      {_kv("Audit events", summary.get("audit_events", 0))}
    </div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Exploitability</th><th>CVE / KEV</th></tr></thead>
    <tbody>{_findings_rows(findings)}</tbody>
  </table>

  <div style="margin-top:40px;color:#555;font-size:11px;text-align:center">
    8π — autonomous offensive-security platform · this report is backed by a tamper-evident audit chain
  </div>
</body></html>"""
