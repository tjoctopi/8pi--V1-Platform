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

from ..attack.catalog import technique_for_finding_type
from ..knowledge.store import KnowledgeStore
from ..schemas.common import StrictModel, iso_now
from ..schemas.findings import Finding, FindingState, Priority
from .corroborate import CONFIRMED, REPORTED, UNCONFIRMED, corroborate, tech_vocabulary

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


class ObservationIntel(StrictModel):
    """A scanner observation with a corroboration confidence (false-positive gate)."""

    name: str
    template_id: str
    severity: str
    #: "corroborated" | "unconfirmed" | "reported" — see intel.corroborate.
    confidence: str = REPORTED
    reason: str = ""


class ToolHealth(StrictModel):
    """Per-tool coverage tally — so ``0 leads`` is honest about tool failures."""

    tool: str
    runs: int = 0
    degraded: int = 0
    skipped: int = 0
    last_error: str = ""


class AssetIntel(StrictModel):
    address: str
    reachable: bool
    services: list[ServiceIntel] = []
    technologies: list[str] = []
    endpoints: list[EndpointIntel] = []
    attack_leads: list[AttackLead] = []
    exposed_items: list[ExposedItem] = []
    #: Scanner observations, each carrying a corroboration confidence.
    observations: list[ObservationIntel] = []
    #: What fronts the asset, if a CDN/WAF was fingerprinted.
    edge: str | None = None
    cves: list[str] = []


class AttackSurface(StrictModel):
    engagement_id: str
    generated_at: str
    assets: list[AssetIntel] = []
    total_leads: int = 0
    confirmed_leads: int = 0
    #: Engagement-wide tool coverage (which scanners ran / degraded / were skipped).
    coverage: list[ToolHealth] = []

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
            if a.edge:
                lines += [f"**Edge:** {a.edge} — strategy adapted "
                          "(focused templates, lead-gated fuzzing)", ""]

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
                confirmed = [o for o in a.observations if o.confidence == CONFIRMED]
                unconfirmed = [o for o in a.observations if o.confidence == UNCONFIRMED]
                reported = [o for o in a.observations if o.confidence == REPORTED]
                lines.append("**Observations**")
                for o in _obs_by_severity(confirmed):
                    lines.append(f"- _{o.severity}_ (corroborated): {o.name}")
                for o in _obs_by_severity(reported):
                    lines.append(f"- _{o.severity}_: {o.name}")
                if unconfirmed:
                    lines.append("- ⚠️ _unconfirmed_ (single-source scanner match, "
                                 "no corroborating fingerprint — do not treat as a "
                                 "confirmed finding):")
                    for o in _obs_by_severity(unconfirmed):
                        lines.append(f"    - _{o.severity}_: {o.name}")
                lines.append("")

        lines += _coverage_markdown(self.coverage)
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
        raw_obs: list[tuple[str, str, str]] = []  # (name, template_id, severity)
        edge_desc: str | None = None
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

            # Edge (CDN/WAF) fingerprint.
            if ftype.startswith("web-edge:"):
                md = f.metadata
                kinds = "/".join(
                    k for k, on in (("CDN", md.get("is_cdn")), ("WAF", md.get("is_waf")))
                    if on
                )
                edge_desc = f"{md.get('vendor') or 'unknown'} {kinds}".strip()
                continue

            # Nuclei / nikto / wpscan observations.
            if ftype.startswith(("web:", "web-observation:")):
                template_id = ftype.split(":", 1)[1] if ":" in ftype else ftype
                raw_obs.append((f.title or ftype, template_id, _severity_of(f)))
                continue

            # Attack leads (vulnerabilities + CVEs).
            klass = _vuln_class(ftype)
            if klass is not None:
                loc, param, method = _lead_location(f)
                status = _status_word(f)
                lead = AttackLead(
                    vuln_class=klass, location=loc, param=param, method=method,
                    technique=str(f.metadata.get("technique")
                                  or technique_for_finding_type(ftype)),
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

        # Corroboration gate: a high/critical observation keeps its severity only
        # if the asset's own fingerprint backs it; otherwise it is unconfirmed.
        vocab = tech_vocabulary(" ".join(
            [*technologies]
            + [x or "" for s in services
               for x in (s.name, s.product, s.version, s.banner)]
        ))
        observations = _corroborated_observations(raw_obs, vocab)

        assets.append(AssetIntel(
            address=asset.address, reachable=reachable, services=services,
            technologies=sorted(set(technologies)),
            endpoints=sorted(endpoints.values(), key=lambda e: e.path),
            attack_leads=leads,
            exposed_items=_dedup_exposed(exposed),
            observations=observations, edge=edge_desc, cves=sorted(set(cves)),
        ))

    # Assets with the most actionable leads first.
    assets.sort(key=lambda a: (-len(a.attack_leads), -len(a.exposed_items)))
    return AttackSurface(
        engagement_id=store.engagement_id, generated_at=iso_now(),
        assets=assets, total_leads=total_leads, confirmed_leads=confirmed_leads,
        coverage=_build_coverage(store),
    )


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def _obs_by_severity(obs: list[ObservationIntel]) -> list[ObservationIntel]:
    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(obs, key=lambda o: (rank.get(o.severity, len(_SEVERITY_ORDER)), o.name))


def _corroborated_observations(
    raw_obs: list[tuple[str, str, str]], tech_tokens: set[str]
) -> list[ObservationIntel]:
    seen: set[tuple[str, str]] = set()
    out: list[ObservationIntel] = []
    for name, template_id, severity in raw_obs:
        key = (template_id, name)
        if key in seen:
            continue
        seen.add(key)
        confidence, reason = corroborate(
            name=name, template_id=template_id, severity=severity,
            tech_tokens=tech_tokens,
        )
        out.append(ObservationIntel(
            name=name, template_id=template_id, severity=severity,
            confidence=confidence, reason=reason,
        ))
    return out


def _build_coverage(store: KnowledgeStore) -> list[ToolHealth]:
    """Aggregate per-tool run outcomes into a coverage report."""

    getter = getattr(store, "tool_runs", None)
    if getter is None:
        return []
    by_tool: dict[str, ToolHealth] = {}
    for rec in getter():
        h = by_tool.setdefault(rec.tool, ToolHealth(tool=rec.tool))
        h.runs += 1
        if rec.outcome == "degraded":
            h.degraded += 1
            h.last_error = rec.detail
        elif rec.outcome == "skipped":
            h.skipped += 1
    return sorted(by_tool.values(), key=lambda h: (-h.degraded, h.tool))


def _coverage_markdown(coverage: list[ToolHealth]) -> list[str]:
    if not coverage:
        return []
    degraded = [h for h in coverage if h.degraded]
    lines = ["## Coverage / tool health", ""]
    if degraded:
        lines.append("⚠️ Some scanners degraded — a `0 leads` result below is a "
                     "coverage gap, not a clean bill of health:")
    lines += ["", "| Tool | Runs | Degraded | Skipped |", "|---|---|---|---|"]
    for h in coverage:
        flag = " ⚠️" if h.degraded else ""
        lines.append(f"| {h.tool}{flag} | {h.runs} | {h.degraded} | {h.skipped} |")
    lines.append("")
    return lines


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
