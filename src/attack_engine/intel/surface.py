"""Attack-surface intelligence dossier (see package docstring).

``build_attack_surface`` reads the knowledge store and produces, per asset, a
structured intelligence record oriented to *offense*: what's running, what's
exposed, and — most importantly — the concrete **attack leads** the offensive
layer can act on (each with the technique, a suggested action, and whether it is
already confirmed or still a candidate). It asserts nothing new; it organises
what the recon/verify/correlate stages already discovered into an actionable map.
"""

from __future__ import annotations

from collections import defaultdict

from ..killchain.plan import _TECHNIQUE_BY_TYPE
from ..knowledge.store import KnowledgeStore
from ..schemas.common import StrictModel, iso_now
from ..schemas.findings import Finding, FindingState, Priority

# --- offensive classification --------------------------------------------------

#: Map a finding-type prefix to a vulnerability class the offensive layer knows.
_CLASS_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("sqli", "sqli"),
    ("xss", "xss"),
    ("path-traversal", "path-traversal"),
    ("lfi", "lfi"),
    ("rfi", "rfi"),
    ("ssrf", "ssrf"),
    ("xxe", "xxe"),
    ("command-injection", "command-injection"),
    ("cmdi", "command-injection"),
    ("ssti", "ssti"),
    ("template-injection", "ssti"),
    ("open-redirect", "open-redirect"),
    ("default-cred", "default-cred"),
    ("cve-", "cve"),
)

#: What an operator / the offensive layer would do with each lead class. These
#: describe the *next* (gated) offensive step — capture itself does none of it.
_SUGGESTED_ACTION: dict[str, str] = {
    "sqli": "SQLMap (boolean/union) + auth-bypass ' OR 1=1-- + DB enumeration (gated)",
    "xss": "Weaponise reflected/stored payload for session/credential theft (gated)",
    "path-traversal": "Read sensitive files (/etc/passwd, config) via the traversal (gated)",
    "lfi": "Include local files / log-poison to RCE (gated)",
    "rfi": "Include a remote payload to achieve RCE (gated)",
    "ssrf": "Pivot to internal services / cloud metadata (169.254.169.254) (gated)",
    "xxe": "Read local files / SSRF via external entity (gated)",
    "command-injection": "Achieve OS command execution / reverse shell (gated)",
    "ssti": "Escalate template evaluation to RCE (gated)",
    "open-redirect": "Chain for phishing / OAuth token theft / SSRF filter bypass",
    "default-cred": "Authenticate with the default credentials and pivot (gated)",
    "cve": "Run the matching exploit module / metasploit check (gated)",
}

#: Interesting discovered paths, keyed by a substring → (category, why-it-matters).
_EXPOSED_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    (".git", "vcs", "Version-control metadata — full source/history disclosure"),
    (".svn", "vcs", "Subversion metadata — source disclosure"),
    (".env", "secrets", "Environment file — likely credentials/API keys"),
    (".htpasswd", "secrets", "Password hashes"),
    (".htaccess", "config", "Server config disclosure"),
    ("backup", "backup", "Backup artefact — may contain source/data"),
    ("dump", "backup", "Database/data dump"),
    (".sql", "backup", "SQL dump — schema/data disclosure"),
    ("config", "config", "Configuration file — credentials/internal detail"),
    ("swagger", "api-spec", "API specification — full endpoint/param inventory"),
    ("openapi", "api-spec", "API specification — full endpoint/param inventory"),
    ("api-docs", "api-spec", "API documentation — endpoint inventory"),
    ("actuator", "mgmt", "Spring Boot Actuator — env/heapdump/mappings exposure"),
    ("phpmyadmin", "admin", "Database admin panel"),
    ("adminer", "admin", "Database admin panel"),
    ("wp-admin", "admin", "WordPress admin"),
    ("admin", "admin", "Administrative interface"),
    ("console", "admin", "Management console"),
    ("jenkins", "ci", "CI server — build/secret exposure, RCE surface"),
    ("grafana", "mgmt", "Metrics dashboard — possible unauth data"),
    ("metrics", "info", "Metrics endpoint — internal telemetry"),
    ("server-status", "info", "Apache status — internal request/IP disclosure"),
    ("phpinfo", "info", "PHP configuration disclosure"),
    ("robots.txt", "info", "Crawler hints — often lists sensitive paths"),
    ("sitemap.xml", "info", "Site structure inventory"),
    ("security.txt", "info", "Security contact / policy"),
)

_PRIORITY_RANK = {
    Priority.PATCH_IMMEDIATELY: 0, Priority.HIGH: 1, Priority.MEDIUM: 2,
    Priority.LOW: 3, Priority.INFORMATIONAL: 4,
}


class ServiceIntel(StrictModel):
    port: int
    protocol: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


class EndpointIntel(StrictModel):
    path: str
    params: list[str] = []
    method: str = "GET"
    status: int | None = None
    source: str = "discovery"  # ffuf | katana | nuclei | probe


class AttackLead(StrictModel):
    """A concrete, actionable target for the offensive layer."""

    vuln_class: str
    location: str            # e.g. "/rest/products/search?q=" or "80/tcp Apache 2.4.49"
    param: str | None = None
    method: str = "GET"
    technique: str = "T1190"  # MITRE ATT&CK
    status: str = "candidate"  # candidate | verified | confirmed
    exploit_prob: float | None = None
    on_kev: bool = False
    suggested_action: str = ""
    evidence: list[str] = []
    finding_id: str = ""


class ExposedItem(StrictModel):
    path: str
    category: str
    why: str


class AssetIntel(StrictModel):
    address: str
    reachable: bool
    services: list[ServiceIntel] = []
    technologies: list[str] = []
    endpoints: list[EndpointIntel] = []
    attack_leads: list[AttackLead] = []
    exposed_items: list[ExposedItem] = []
    #: severity → observation names (nuclei/nikto/wpscan informational signal).
    observations: dict[str, list[str]] = {}
    cves: list[str] = []


class AttackSurface(StrictModel):
    engagement_id: str
    generated_at: str
    assets: list[AssetIntel] = []
    total_leads: int = 0
    confirmed_leads: int = 0

    def to_markdown(self) -> str:
        lines: list[str] = [
            f"# Attack-Surface Intelligence — {self.engagement_id}",
            "",
            f"- Generated: {self.generated_at}",
            f"- Assets: {len(self.assets)}  ·  "
            f"Attack leads: {self.total_leads} ({self.confirmed_leads} confirmed)",
            "",
        ]
        for a in self.assets:
            lines += [f"## {a.address}  ({'reachable' if a.reachable else 'unreachable'})", ""]

            if a.services:
                lines.append("**Services**")
                for s in a.services:
                    ver = f" {s.product or ''} {s.version or ''}".rstrip()
                    lines.append(f"- `{s.port}/{s.protocol}` {s.name or ''}{ver}".rstrip())
                lines.append("")
            if a.technologies:
                lines += [f"**Technology:** {', '.join(a.technologies)}", ""]

            if a.attack_leads:
                lines.append("**Attack leads** (offensive layer targets)")
                lines.append("| # | Class | Status | Location | Technique | KEV | Prob "
                             "| Suggested action |")
                lines.append("|---|---|---|---|---|---|---|---|")
                for i, ld in enumerate(a.attack_leads, 1):
                    prob = f"{ld.exploit_prob:.2f}" if ld.exploit_prob is not None else "—"
                    lines.append(
                        f"| {i} | {ld.vuln_class} | {ld.status} | `{ld.location}` | "
                        f"{ld.technique} | {'yes' if ld.on_kev else '—'} | {prob} | "
                        f"{ld.suggested_action} |"
                    )
                lines.append("")

            if a.exposed_items:
                lines.append("**Exposed items**")
                for e in a.exposed_items:
                    lines.append(f"- `/{e.path}` — *{e.category}*: {e.why}")
                lines.append("")

            if a.endpoints:
                lines.append(f"**Endpoints** ({len(a.endpoints)})")
                for ep in a.endpoints[:40]:
                    q = f"?{'&'.join(p + '=' for p in ep.params)}" if ep.params else ""
                    st = f" [{ep.status}]" if ep.status is not None else ""
                    lines.append(f"- `{ep.method} {ep.path}{q}`{st}  ({ep.source})")
                if len(a.endpoints) > 40:
                    lines.append(f"- … and {len(a.endpoints) - 40} more")
                lines.append("")

            if a.cves:
                lines += [f"**CVEs:** {', '.join(a.cves)}", ""]

            if a.observations:
                lines.append("**Observations**")
                for sev in ("critical", "high", "medium", "low", "info", "unknown"):
                    names = a.observations.get(sev)
                    if names:
                        lines.append(f"- _{sev}_: {', '.join(sorted(set(names)))}")
                lines.append("")
        return "\n".join(lines)


# --- construction --------------------------------------------------------------


def _vuln_class(ftype: str) -> str | None:
    low = ftype.lower()
    for prefix, klass in _CLASS_BY_PREFIX:
        if low.startswith(prefix):
            return klass
    return None


def _exposed_for(path: str) -> tuple[str, str] | None:
    low = path.lower()
    for sig, category, why in _EXPOSED_SIGNATURES:
        if sig in low:
            return category, why
    return None


def _status_word(f: Finding) -> str:
    if f.state is FindingState.CONFIRMED:
        return "confirmed"
    if f.state is FindingState.VERIFIED:
        return "verified"
    return "candidate"


def _lead_location(f: Finding) -> tuple[str, str | None, str]:
    """Return (location, param, method) for a lead finding."""

    md = f.metadata
    param = md.get("param")
    path = md.get("path")
    method = str(md.get("method", "GET")).upper()
    if path:
        loc = f"{path}?{param}=" if param else str(path)
        return loc, (str(param) if param else None), method
    if f.service:
        return f"{f.service}", None, method
    return f.type, (str(param) if param else None), method


def _severity_of(f: Finding) -> str:
    sev = f.metadata.get("severity")
    if isinstance(sev, str) and sev:
        return sev.lower()
    if f.priority is Priority.PATCH_IMMEDIATELY:
        return "critical"
    if f.priority is not None:
        return str(f.priority.value)
    return "unknown"


def build_attack_surface(store: KnowledgeStore) -> AttackSurface:
    """Aggregate the blackboard into a per-asset offensive intelligence dossier."""

    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in store.findings():
        by_asset[f.asset].append(f)

    assets: list[AssetIntel] = []
    total_leads = 0
    confirmed_leads = 0

    for asset in store.assets():
        findings = by_asset.get(asset.address, []) + by_asset.get(asset.id, [])
        reachable = store.graph.is_reachable(asset.id)

        services = [
            ServiceIntel(port=s.port, protocol=s.protocol, name=s.name,
                         product=s.product, version=s.version, banner=s.banner)
            for s in asset.services
        ]

        technologies: list[str] = []
        endpoints: dict[tuple[str, str], EndpointIntel] = {}
        leads: list[AttackLead] = []
        exposed: list[ExposedItem] = []
        observations: dict[str, list[str]] = defaultdict(list)
        cves: list[str] = []

        for f in findings:
            ftype = f.type

            # Technology signal from web-tech findings.
            if ftype.startswith("web-tech:"):
                tech = f.metadata.get("tech")
                if isinstance(tech, list):
                    technologies.extend(str(t) for t in tech)
                elif f.title:
                    technologies.append(f.title)
                continue

            # Discovered path → endpoint + maybe an exposed item.
            if ftype.startswith("web-path:"):
                path = "/" + ftype[len("web-path:"):].lstrip("/")
                endpoints.setdefault((path, "GET"), EndpointIntel(
                    path=path, method="GET",
                    status=_int_or_none(f.metadata.get("status")), source="ffuf"))
                hit = _exposed_for(path)
                if hit is not None:
                    exposed.append(ExposedItem(path=path.lstrip("/"),
                                               category=hit[0], why=hit[1]))
                continue

            # Crawled endpoint intel.
            if ftype.startswith("web-endpoint:"):
                path = str(f.metadata.get("path") or ("/" + ftype[len("web-endpoint:"):]))
                params = [str(p) for p in (f.metadata.get("params") or [])]
                method = str(f.metadata.get("method", "GET")).upper()
                endpoints[(path, method)] = EndpointIntel(
                    path=path, params=params, method=method, source="katana")
                continue

            # Nuclei / nikto / wpscan observations.
            if ftype.startswith(("web:", "web-observation:")):
                observations[_severity_of(f)].append(f.title or ftype)
                continue

            # Attack leads (vulnerabilities + CVEs).
            klass = _vuln_class(ftype)
            if klass is not None:
                loc, param, method = _lead_location(f)
                status = _status_word(f)
                lead = AttackLead(
                    vuln_class=klass, location=loc, param=param, method=method,
                    technique=str(f.metadata.get("technique")
                                  or _TECHNIQUE_BY_TYPE.get(ftype, "T1190")),
                    status=status, exploit_prob=f.exploit_prob, on_kev=f.on_kev,
                    suggested_action=_SUGGESTED_ACTION.get(klass, ""),
                    evidence=list(f.evidence), finding_id=f.id,
                )
                leads.append(lead)
                if klass == "cve":
                    cves.append(ftype)
                # Also record the injectable endpoint in the endpoint map.
                if param and loc.startswith("/"):
                    p = loc.split("?", 1)[0]
                    ep = endpoints.setdefault((p, method),
                                              EndpointIntel(path=p, method=method, source="probe"))
                    if param not in ep.params:
                        ep.params.append(param)

        # Rank leads: confirmed first, then by exploit probability.
        leads.sort(key=lambda ld: (
            0 if ld.status == "confirmed" else 1 if ld.status == "verified" else 2,
            -(ld.exploit_prob or 0.0),
        ))
        total_leads += len(leads)
        confirmed_leads += sum(1 for ld in leads if ld.status == "confirmed")

        assets.append(AssetIntel(
            address=asset.address, reachable=reachable, services=services,
            technologies=sorted(set(technologies)),
            endpoints=sorted(endpoints.values(), key=lambda e: e.path),
            attack_leads=leads,
            exposed_items=_dedup_exposed(exposed),
            observations=dict(observations), cves=sorted(set(cves)),
        ))

    # Assets with the most actionable leads first.
    assets.sort(key=lambda a: (-len(a.attack_leads), -len(a.exposed_items)))
    return AttackSurface(
        engagement_id=store.engagement_id, generated_at=iso_now(),
        assets=assets, total_leads=total_leads, confirmed_leads=confirmed_leads,
    )


def _int_or_none(v: object) -> int | None:
    return v if isinstance(v, int) else None


def _dedup_exposed(items: list[ExposedItem]) -> list[ExposedItem]:
    seen: set[str] = set()
    out: list[ExposedItem] = []
    for it in items:
        if it.path in seen:
            continue
        seen.add(it.path)
        out.append(it)
    return out
