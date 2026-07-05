"""C-10 Reporting: per-engagement purple-team deliverable (JSON + HTML + PDF)."""
import io
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from db import db
from store import doc_out, docs_out, get_engagement, get_roe, now_iso
from audit import verify_chain
from threat_model import build_map

router = APIRouter()

_SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}


async def build_report(engagement_id):
    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    roe = await get_roe(eng)
    assets = await db.assets.find({"engagement_id": engagement_id}).to_list(3000)
    findings = await db.findings.find({"engagement_id": engagement_id}).to_list(5000)
    findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 9))
    runs = await db.agent_runs.find({"engagement_id": engagement_id}).sort("started_at", 1).to_list(200)
    approvals = await db.approvals.find({"engagement_id": engagement_id}).to_list(500)
    risk_map = await build_map(engagement_id)
    chain = await verify_chain(engagement_id)
    audit_count = await db.audit_events.count_documents({"engagement_id": engagement_id})

    sev_counts = {}
    for f in findings:
        if f.get("status") in ("closed", "false-positive"):
            continue
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    return {
        "generated_at": now_iso(),
        "engagement": doc_out(eng),
        "roe": doc_out(roe),
        "summary": {
            "assets": len(assets),
            "findings_total": len(findings),
            "findings_open_by_severity": sev_counts,
            "findings_closed": sum(1 for f in findings if f.get("status") == "closed"),
            "agent_runs": len(runs),
            "audit_events": audit_count,
            "audit_chain_valid": chain.get("valid"),
        },
        "assets": docs_out(assets),
        "findings": docs_out(findings),
        "risk_map": risk_map,
        "agent_runs": docs_out(runs),
        "approvals": docs_out(approvals),
        "audit": chain,
    }


@router.get("/engagements/{eid}/report")
async def report_json(eid: str):
    return await build_report(eid)


@router.get("/engagements/{eid}/report.html", response_class=HTMLResponse)
async def report_html(eid: str):
    r = await build_report(eid)
    eng, roe, s = r["engagement"], r["roe"], r["summary"]
    rows = ""
    for f in r["findings"]:
        rows += (f"<tr><td class='sev {f.get('severity')}'>{f.get('severity','').upper()}</td>"
                 f"<td>{f.get('title','')}</td><td>{f.get('exploitability','')}</td>"
                 f"<td>{f.get('status','')}</td><td>{', '.join(f.get('cve_refs',[]) or [])}</td>"
                 f"<td>{f.get('remediation','')}</td></tr>")
    sev_line = ", ".join([f"{k.upper()}: {v}" for k, v in s["findings_open_by_severity"].items()]) or "none"
    html = f"""<!doctype html><html><head><meta charset=utf-8>
<title>8pi Engagement Report — {eng['name']}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;margin:0;padding:40px}}
h1,h2{{font-family:'Barlow Condensed',sans-serif;text-transform:uppercase;letter-spacing:.02em}}
h1{{color:#fff;border-bottom:2px solid #007AFF;padding-bottom:8px}}
.card{{background:#121212;border:1px solid rgba(255,255,255,.1);padding:20px;margin:16px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}}
th{{color:#8E8E93;text-transform:uppercase;font-size:11px;letter-spacing:.1em}}
.sev{{font-weight:700}} .crit{{color:#FF453A}} .high{{color:#FF453A}} .med{{color:#FF9F0A}} .low{{color:#0A84FF}} .info{{color:#8E8E93}}
.badge{{display:inline-block;padding:2px 8px;border:1px solid #007AFF;color:#0A84FF;font-size:11px;margin-right:6px}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#32D74B}}
</style></head><body>
<h1>8pi Purple-Team Engagement Report</h1>
<p><b>{eng['name']}</b> — status <span class=badge>{eng['status']}</span> · generated {r['generated_at']}</p>
<div class=card><h2>Scope / Rules of Engagement</h2>
<p>Max intensity: <b>{roe.get('max_intensity') if roe else '-'}</b> · Signed by: {roe.get('signed_by') if roe else '-'} at {roe.get('signed_at') if roe else '-'}</p>
<p>Allowlist: <span class=mono>{', '.join(roe.get('scope_allowlist',[])) if roe else ''}</span></p>
<p>Allowed tools: <span class=mono>{', '.join(roe.get('allowed_tools',[])) if roe else ''}</span></p></div>
<div class=card><h2>Summary</h2>
<p>Assets: <b>{s['assets']}</b> · Open findings: <b>{sev_line}</b> · Closed: <b>{s['findings_closed']}</b></p>
<p>Agent runs: <b>{s['agent_runs']}</b> · Audit events: <b>{s['audit_events']}</b> · Audit chain valid: <b class=mono>{s['audit_chain_valid']}</b></p></div>
<div class=card><h2>Findings</h2>
<table><thead><tr><th>Sev</th><th>Finding</th><th>Exploitability</th><th>Status</th><th>CVE</th><th>Remediation</th></tr></thead>
<tbody>{rows or '<tr><td colspan=6>No findings.</td></tr>'}</tbody></table></div>
<p class=mono>Reproducible from tamper-evident audit log · head hash {r['audit'].get('head_hash','')[:24]}…</p>
</body></html>"""
    return HTMLResponse(content=html)


@router.get("/engagements/{eid}/report.pdf")
async def report_pdf(eid: str):
    r = await build_report(eid)
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
    except Exception:
        raise HTTPException(status_code=501, detail="PDF engine unavailable")
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 25 * mm
    eng, s = r["engagement"], r["summary"]

    def line(txt, size=10, dy=6, bold=False):
        nonlocal y
        if y < 25 * mm:
            c.showPage(); y = h - 25 * mm
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(20 * mm, y, txt[:110]); y -= dy * mm

    line("8pi Purple-Team Engagement Report", 16, 10, True)
    line(f"{eng['name']}  ·  status {eng['status']}  ·  {r['generated_at']}", 9, 8)
    line("Summary", 13, 8, True)
    line(f"Assets: {s['assets']}   Findings total: {s['findings_total']}   Closed: {s['findings_closed']}", 9)
    line(f"Open by severity: {s['findings_open_by_severity']}", 9)
    line(f"Audit events: {s['audit_events']}   Chain valid: {s['audit_chain_valid']}", 9, 10)
    line("Findings", 13, 8, True)
    for f in r["findings"][:40]:
        line(f"[{f.get('severity','').upper()}] {f.get('title','')} — {f.get('exploitability','')} — {f.get('status','')}", 9, 5)
        line(f"    Fix: {f.get('remediation','')}", 8, 6)
    c.showPage(); c.save(); buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename=8pi-report-{eid[:8]}.pdf"})
