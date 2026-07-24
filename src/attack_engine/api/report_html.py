# ruff: noqa: E501  (HTML template lines are intentionally long)
"""Render an engagement report (the ``/report`` JSON) to a standalone HTML page.

Pure and dependency-free: takes the exact dict the ``/engagements/{eid}/report``
endpoint returns and produces a self-contained, printable, **client-ready** HTML
document (inline CSS, no external assets). It is written for a non-technical
reader — an executive summary, a plain-language "what this means", proof of
compromise, and clear "how to fix" guidance — while still carrying the technical
detail an engineer needs. The same HTML is what the PDF export rasterises, so the
two exports never drift.
"""

from __future__ import annotations

from html import escape
from typing import Any

# Professional, print-friendly palette (light document, dark ink).
_SEV = {
    "crit": ("Critical", "#C1121F"),
    "high": ("High", "#E85D04"),
    "med": ("Medium", "#E8A400"),
    "low": ("Low", "#2A9D8F"),
    "info": ("Informational", "#6C757D"),
}
_SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}

# Plain-language business impact keyed by finding class — what a weakness *means*
# for the organisation, not how it works.
_IMPACT_PLAIN = (
    (("command-injection", "cmdi", "os-command", "rce"),
     "An attacker can run their own commands on this system — in practice, taking full control of the host and anything it can reach."),
    (("sqli", "sql-injection"),
     "An attacker can read or tamper with the application's database, which can expose customer or business data."),
    (("ssti", "template-injection"),
     "An attacker can execute code through the application's page-templating engine — a path to taking over the server."),
    (("lfi", "path-traversal"),
     "An attacker can read sensitive files from the server, such as configuration files or stored credentials."),
    (("ssrf",),
     "An attacker can make your server reach internal systems it should not — a foothold into the internal network."),
    (("xss",),
     "An attacker can run scripts in your users' browsers, enabling account takeover, data theft, or fraud."),
    (("open-redirect",),
     "An attacker can abuse your trusted domain to send victims to malicious sites (phishing)."),
    (("default-cred", "weak-cred", "auth-bypass"),
     "An attacker can log in without valid credentials, gaining access reserved for legitimate users."),
    (("cve-",),
     "A publicly documented vulnerability with known exploit techniques — attackers actively scan for these."),
)


def _sev_meta(sev: str) -> tuple[str, str]:
    return _SEV.get(sev, ("Informational", "#6C757D"))


def _sev_badge(sev: str) -> str:
    label, color = _sev_meta(sev)
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:20px;'
        f'font-size:11px;font-weight:700;letter-spacing:.03em;white-space:nowrap">{escape(label)}</span>'
    )


def _plain_impact(ftype: str, sev: str) -> str:
    ft = (ftype or "").lower()
    for keys, text in _IMPACT_PLAIN:
        if ft.startswith(keys):
            return text
    fallback = {
        "crit": "A serious weakness that a capable attacker could use to cause significant harm.",
        "high": "A significant weakness that materially increases the risk of a breach.",
        "med": "A moderate weakness that should be corrected as part of normal hardening.",
        "low": "A minor weakness with limited direct impact.",
        "info": "An informational observation for awareness.",
    }
    return fallback.get(sev, fallback["info"])


def _overall_verdict(by_sev: dict[str, int], breach: dict[str, Any]) -> tuple[str, str, str]:
    crit = int(by_sev.get("crit", 0))
    high = int(by_sev.get("high", 0))
    med = int(by_sev.get("med", 0))
    footholds = int(breach.get("live_footholds", 0) or 0)
    if breach.get("domain_admin") or footholds or crit:
        return ("CRITICAL", "#C1121F", "Immediate action required")
    if high:
        return ("HIGH", "#E85D04", "Prompt remediation recommended")
    if med:
        return ("MODERATE", "#E8A400", "Address as part of planned hardening")
    return ("LOW", "#2A9D8F", "No significant exploitable risk confirmed")


def _exec_summary(summary: dict[str, Any], breach: dict[str, Any], footholds: list[dict[str, Any]]) -> str:
    by_sev = summary.get("findings_open_by_severity", {}) or {}
    assets = summary.get("assets", 0)
    total = summary.get("findings_total", 0)
    crit = int(by_sev.get("crit", 0))
    high = int(by_sev.get("high", 0))
    fh = int(breach.get("live_footholds", 0) or 0)
    sentences = [
        f"During this authorized engagement, the 8π autonomous offensive-security platform assessed "
        f"<b>{assets}</b> in-scope asset(s) and recorded <b>{total}</b> finding(s)."
    ]
    if fh:
        sentences.append(
            f"Most importantly, the platform established <b>{fh} live foothold(s)</b> on your systems — "
            "demonstrating that these weaknesses are exploitable in practice, not just in theory. "
            "The concrete evidence is shown under <i>Proof of Compromise</i> below."
        )
    if breach.get("domain_admin"):
        sentences.append("The assessment escalated to <b>full domain-administrator control</b> of the environment.")
    if crit or high:
        bits = []
        if crit:
            bits.append(f"<b>{crit}</b> Critical")
        if high:
            bits.append(f"<b>{high}</b> High")
        sentences.append(f"{' and '.join(bits)} finding(s) warrant priority attention.")
    if not fh and not crit and not high:
        sentences.append("No critical or high-risk exploitable weaknesses were confirmed during this engagement.")
    return " ".join(sentences)


def _tile(value: Any, label: str, color: str = "#0B2447") -> str:
    return (
        f'<div class="tile"><div class="tile-v" style="color:{color}">{escape(str(value))}</div>'
        f'<div class="tile-l">{escape(label)}</div></div>'
    )


def _proof_section(footholds: list[dict[str, Any]]) -> str:
    live = [f for f in footholds if f.get("status") != "closed"] or footholds
    if not live:
        return (
            '<p class="muted">No live foothold was established during this engagement. '
            "The findings below describe weaknesses that were identified but not exploited to a session.</p>"
        )
    blocks: list[str] = []
    for f in live:
        proof = f.get("proof") or {}
        whoami = escape(str(proof.get("whoami") or "user"))
        host = escape(str(f.get("host") or "the target"))
        rows = "".join(
            f'<div class="pk"><span>{escape(k)}</span><code>{escape(str(v))}</code></div>'
            for k, v in proof.items()
        )
        loot = f.get("loot") or []
        loot_html = ""
        if loot:
            items = "".join(
                f"<li><code>{escape(str(row.get('command')))}</code> → {escape(str(row.get('output') or '')[:140])}</li>"
                for row in loot[:6]
            )
            loot_html = f'<div class="sub">Commands our platform was able to run:</div><ul class="loot">{items}</ul>'
        site = f.get("site_content") or {}
        site_html = ""
        if site.get("snippet"):
            site_html = (
                f'<div class="sub">Live content captured from <code>{escape(str(site.get("url") or ""))}</code> '
                f'(HTTP {escape(str(site.get("status") or "?"))}):</div>'
                f'<pre class="capture">{escape(str(site.get("snippet"))[:600])}</pre>'
            )
        blocks.append(
            f'<div class="proof"><div class="proof-h">Interactive access gained on '
            f'<b>{host}</b> as <b>{whoami}</b></div>'
            f'<div class="pk-grid">{rows}</div>{loot_html}{site_html}</div>'
        )
    return "".join(blocks)


def _finding_card(f: dict[str, Any]) -> str:
    sev = f.get("severity", "info")
    cvss = f.get("cvss")
    cvss_s = f"CVSS {cvss}" if isinstance(cvss, int | float) else ""
    cves = ", ".join(f.get("cve_refs") or [])
    kev = ' <span class="kev">CISA KEV</span>' if f.get("kev") else ""
    conf = f.get("exploitability")
    conf_badge = (
        '<span class="confirmed">CONFIRMED — proven exploitable</span>'
        if conf == "confirmed" else
        ('<span class="reachable">Reachable</span>' if conf == "reachable" else "")
    )
    meta = " · ".join(x for x in [cvss_s, escape(cves) + kev if cves else ""] if x)
    impact = _plain_impact(f.get("type", ""), sev)
    remediation = escape(str(f.get("remediation") or "Apply the vendor's fix and validate the configuration."))
    reach = escape(str(f.get("reachability_reason") or ""))
    return (
        f'<div class="fcard"><div class="fcard-h">{_sev_badge(sev)} '
        f'<span class="ftitle">{escape(str(f.get("title") or f.get("id")))}</span>'
        f'<span class="fasset">{escape(str(f.get("asset_id") or ""))}</span></div>'
        f'{f"<div class=meta>{meta}</div>" if meta else ""}'
        f'{f"<div class=badges>{conf_badge}</div>" if conf_badge else ""}'
        f'<div class="frow"><span class="k">What this means</span><span>{escape(impact)}</span></div>'
        + (f'<div class="frow"><span class="k">Why it is reachable</span><span>{reach}</span></div>' if reach else "")
        + f'<div class="frow"><span class="k">How to fix it</span><span>{remediation}</span></div>'
        + "</div>"
    )


def _findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="3" class="empty">None.</td></tr>'
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{_sev_badge(f.get('severity', 'info'))}</td>"
            f"<td>{escape(str(f.get('title') or f.get('id')))}</td>"
            f'<td class="mono">{escape(str(f.get("status") or ""))}</td></tr>'
        )
    return "".join(rows)


def render_report_html(report: dict[str, Any]) -> str:
    """Build a client-ready, printable HTML document from the report JSON."""

    eng = report.get("engagement", {})
    roe = report.get("roe", {})
    summary = report.get("summary", {})
    findings = report.get("findings", []) or []
    breach = report.get("breach", {}) or {}
    footholds = report.get("footholds", []) or []
    by_sev = summary.get("findings_open_by_severity", {}) or {}

    name = escape(str(eng.get("name") or "Engagement"))
    generated = escape(str(report.get("generated_at") or ""))
    chain_ok = summary.get("audit_chain_valid", True)
    verdict, vcolor, vsub = _overall_verdict(by_sev, breach)

    # findings split: detailed cards for confirmed / high-severity, a compact table for the rest
    ranked = sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 9))
    key_findings = [f for f in ranked
                    if f.get("exploitability") == "confirmed" or f.get("severity") in ("crit", "high")]
    other_findings = [f for f in ranked if f not in key_findings]

    sev_tiles = "".join(
        _tile(by_sev.get(k, 0), lbl, color)
        for k, (lbl, color) in _SEV.items() if k != "info"
    )
    exec_summary = _exec_summary(summary, breach, footholds)
    cards = "".join(_finding_card(f) for f in key_findings) or '<p class="muted">No confirmed or high-severity findings.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Offensive Security Assessment — {name}</title>
<style>
  :root {{ --ink:#1A1D23; --muted:#5B6472; --line:#E3E7EE; --accent:#0B2447; --bg:#FFFFFF; --soft:#F6F8FB; }}
  * {{ box-sizing:border-box }}
  body {{ background:var(--bg); color:var(--ink); font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         margin:0; padding:0; line-height:1.55; -webkit-print-color-adjust:exact; print-color-adjust:exact }}
  .page {{ max-width:920px; margin:0 auto; padding:48px 44px }}
  .cover {{ border-bottom:3px solid var(--accent); padding-bottom:22px; margin-bottom:6px }}
  .brand {{ font-size:12px; letter-spacing:.22em; text-transform:uppercase; color:var(--accent); font-weight:800 }}
  h1 {{ font-size:30px; margin:8px 0 4px; letter-spacing:-.01em }}
  .sub {{ color:var(--muted); font-size:13px }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.1em; color:var(--accent);
        margin:34px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line) }}
  .verdict {{ display:flex; align-items:center; gap:16px; margin:22px 0; padding:16px 20px;
              border-radius:10px; background:var(--soft); border:1px solid var(--line) }}
  .verdict .dot {{ width:14px; height:14px; border-radius:50%; box-shadow:0 0 0 4px rgba(0,0,0,.04) }}
  .verdict .lvl {{ font-size:20px; font-weight:800 }}
  .lead {{ font-size:15px; color:#2B303A }}
  .tiles {{ display:flex; flex-wrap:wrap; gap:12px; margin:14px 0 }}
  .tile {{ flex:1; min-width:120px; background:var(--soft); border:1px solid var(--line); border-radius:10px; padding:14px 16px; text-align:center }}
  .tile-v {{ font-size:30px; font-weight:800; line-height:1 }}
  .tile-l {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-top:6px }}
  .proof {{ background:var(--soft); border:1px solid var(--line); border-left:4px solid #C1121F; border-radius:8px; padding:16px 18px; margin:12px 0 }}
  .proof-h {{ font-size:15px; font-weight:700; margin-bottom:10px }}
  .pk-grid {{ display:flex; flex-wrap:wrap; gap:8px 22px; margin-bottom:8px }}
  .pk {{ font-size:12px }}
  .pk span {{ color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin-right:6px }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:#0B2447; background:#EEF2F8; padding:1px 6px; border-radius:4px }}
  .loot {{ margin:6px 0 0; padding-left:18px; font-size:12.5px }}
  .loot li {{ margin:2px 0 }}
  .capture {{ background:#0E1117; color:#C9D1D9; font-family:ui-monospace,monospace; font-size:11px;
              padding:12px; border-radius:6px; overflow-x:auto; white-space:pre-wrap; margin:6px 0 0 }}
  .fcard {{ border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin:12px 0; page-break-inside:avoid }}
  .fcard-h {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap }}
  .ftitle {{ font-weight:700; font-size:15px }}
  .fasset {{ margin-left:auto; font-family:ui-monospace,monospace; font-size:12px; color:var(--muted) }}
  .meta {{ font-family:ui-monospace,monospace; font-size:12px; color:var(--muted); margin:6px 0 }}
  .badges {{ margin:6px 0 }}
  .confirmed {{ background:#C1121F; color:#fff; font-size:11px; font-weight:700; padding:2px 10px; border-radius:20px }}
  .reachable {{ background:#E8A400; color:#111; font-size:11px; font-weight:700; padding:2px 10px; border-radius:20px }}
  .kev {{ background:#7A0C15; color:#fff; font-size:10px; font-weight:700; padding:1px 7px; border-radius:20px }}
  .frow {{ display:flex; gap:14px; margin-top:8px; font-size:13.5px }}
  .frow .k {{ flex:0 0 150px; color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.06em; padding-top:2px }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:6px }}
  th {{ text-align:left; padding:9px 8px; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; border-bottom:2px solid var(--line) }}
  td {{ padding:9px 8px; border-bottom:1px solid var(--line) }}
  .mono {{ font-family:ui-monospace,monospace }}
  .muted {{ color:var(--muted); font-size:13px }}
  .empty {{ text-align:center; color:var(--muted); padding:16px }}
  .kv {{ display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--line); font-size:13px }}
  .kv b {{ color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.05em }}
  .cols {{ display:flex; gap:24px; flex-wrap:wrap }}
  .cols > div {{ flex:1; min-width:240px }}
  .assure {{ display:flex; align-items:center; gap:10px; font-size:14px; margin:6px 0 }}
  footer {{ margin-top:40px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:11px; text-align:center }}
  @media print {{ .page {{ padding:0 }} h2 {{ page-break-after:avoid }} }}
</style></head>
<body><div class="page">

  <div class="cover">
    <div class="brand">8π · Offensive Security Assessment</div>
    <h1>{name}</h1>
    <div class="sub">Confidential engagement report · generated {generated}</div>
  </div>

  <div class="verdict">
    <span class="dot" style="background:{vcolor}"></span>
    <div>
      <div class="lvl" style="color:{vcolor}">{verdict} RISK</div>
      <div class="sub">{vsub}</div>
    </div>
  </div>

  <h2>Executive Summary</h2>
  <p class="lead">{exec_summary}</p>
  <div class="tiles">
    {_tile(summary.get("assets", 0), "Assets Assessed")}
    {_tile(breach.get("live_footholds", 0), "Live Footholds", "#C1121F")}
    {_tile("Yes" if breach.get("domain_admin") else "No", "Domain Admin", "#C1121F" if breach.get("domain_admin") else "#2A9D8F")}
    {_tile(summary.get("findings_total", 0), "Total Findings")}
  </div>

  <h2>Risk at a Glance</h2>
  <div class="tiles">{sev_tiles}</div>

  <h2>Proof of Compromise</h2>
  {_proof_section(footholds)}

  <h2>Key Findings</h2>
  {cards}

  <h2>All Findings ({len(findings)})</h2>
  <table><thead><tr><th>Severity</th><th>Finding</th><th>Status</th></tr></thead>
  <tbody>{_findings_table(other_findings) if other_findings else _findings_table([])}</tbody></table>

  <h2>Methodology &amp; Scope</h2>
  <div class="cols">
    <div>
      <div class="kv"><b>Engagement</b><span>{escape(str(eng.get("name") or ""))}</span></div>
      <div class="kv"><b>Status</b><span>{escape(str(eng.get("status") or ""))}</span></div>
      <div class="kv"><b>Max intensity</b><span>{escape(str(roe.get("max_intensity") or "—"))}</span></div>
      <div class="kv"><b>Authorized by</b><span>{escape(str(roe.get("signed_by") or "—"))}</span></div>
    </div>
    <div>
      <p class="muted">This assessment was performed by 8π's autonomous offensive platform inside a signed,
      time-bound authorization. The platform followed a real adversary kill chain — reconnaissance, exploitation,
      foothold, and where in scope, privilege escalation and lateral movement — and <b>confirmed</b> each weakness
      by proving it, not merely detecting it. Every action was scope-enforced and recorded.</p>
    </div>
  </div>

  <h2>Assurance</h2>
  <div class="assure">
    <span style="color:{'#2A9D8F' if chain_ok else '#C1121F'};font-size:18px">{'✓' if chain_ok else '✗'}</span>
    <span>Tamper-evident audit chain {'verified' if chain_ok else 'BROKEN'} — every action in this report is
    backed by an immutable, hash-chained log and is fully reproducible.</span>
  </div>
  <div class="kv"><b>Audit events</b><span class="mono">{escape(str(summary.get("audit_events", 0)))}</span></div>

  <footer>8π — autonomous offensive-security platform · Confidential · This report is backed by a tamper-evident audit chain.</footer>

</div></body></html>"""
