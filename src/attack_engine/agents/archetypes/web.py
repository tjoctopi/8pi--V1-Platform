"""Web Inquisitor — the web tool-driver archetype (spec §4, step 5a).

Enumerates web surface and OWASP-class issues with templated scanners (Nuclei)
and, optionally, Nikto/WPScan. It *proposes* findings from tool output — it
confirms nothing itself (rule #1). When it spots a parameterised endpoint that a
templated check flags as injection-prone, it proposes a ``sqli-candidate`` lead
for the Exploit-Confirmer to (gated) confirm. Read-only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

from ...errors import RateLimitExceededError, RoEViolationError
from ...intel.edge import EdgeProfile, detect_edge
from ...logging import get_logger
from ...schemas.findings import Finding, Priority
from ...schemas.tools import ToolProfile
from ...toolrunner.wrappers.http_probe import HttpProbeWrapper
from ..base import Agent
from ..discovery import OPENAPI_PATHS, parse_openapi
from ..injection import InjectionPoint, build_injection_points

_log = get_logger("agent.web_inquisitor")

#: Upper bound on injection points actively screened per host — a safety cap on
#: probe volume (each point costs a few read-only requests).
_DETECT_LIMIT = 24
_TRUE_SUFFIX = "' AND '1'='1"
_FALSE_SUFFIX = "' AND '1'='2"

_SEVERITY_TO_PRIORITY = {
    "critical": Priority.HIGH,
    "high": Priority.HIGH,
    "medium": Priority.MEDIUM,
    "low": Priority.LOW,
    "info": Priority.INFORMATIONAL,
}
_SQLI_HINTS = ("sqli", "sql-injection", "sql_injection", "injection")


class WebInquisitor(Agent):
    def _execute(self, targets: list[str]) -> None:
        # Fingerprint the edge ONCE PER HOST before scanning any of its ports. A
        # CDN answers most reliably on 443, and a host either sits behind an edge
        # or it doesn't — detecting per-port is flaky (an origin-only port like
        # :81 hides the cf-ray that :443 shows) and would let dalfox run on ports
        # we already know are WAF'd. One detection, inherited by every port.
        self._edge_by_host: dict[str, EdgeProfile] = {}
        for host in sorted({_split_target(t)[0] for t in targets}):
            self._edge_by_host[host] = self._detect_host_edge(host)
        for target in targets:
            self._scan(target)

    def _scan(self, target: str) -> None:
        host, scheme, port = _split_target(target)
        edge = self._edge_by_host.get(host) or EdgeProfile()
        # Drive every web tool bound to this agent's spec. Passing the bare host
        # keeps scope enforcement first; each wrapper builds its own URL. Adding
        # coverage is adding a tool to the spec — not new agent code (rule #3).
        # Crawl BEFORE fuzzing so lead-gated tools (dalfox) can see the surface.
        self._run_katana(host, scheme, port, edge)
        # An API's own spec is the richest endpoint/param inventory there is.
        self._ingest_api_specs(host, scheme, port)
        self._run_nuclei(host, scheme, port, edge)
        self._run_nikto(host, scheme, port)
        self._run_wpscan(host, scheme, port)
        self._run_dalfox(host, scheme, port, edge)
        # Actively screen injection points (read-only) and raise oracle-verifiable
        # hypotheses — this is what turns "surface enumerated" into "breachable?".
        self._detect_injections(host, scheme, port)

    # --- edge fingerprint + adaptive strategy ---------------------------------

    def _detect_host_edge(self, host: str) -> EdgeProfile:
        """Detect a CDN/WAF for a host from response headers (read-only probes).

        Tries https then http (CDNs answer most reliably on 443). The first
        response that reveals an edge wins; records a ``web-edge:`` finding so the
        dossier shows what fronts the asset. A failed/blocked probe or a bare
        origin yields an empty profile.
        """

        if "http_probe" not in self.spec.tools:
            return EdgeProfile()
        for scheme in ("https", "http"):
            try:
                result = self.run_tool("http_probe", host, ToolProfile(args={
                    "scheme": scheme, "path": "/", "include_headers": True}))
            except (RateLimitExceededError, RoEViolationError):
                return EdgeProfile()
            if result is None:
                continue
            edge = detect_edge(_header_block(HttpProbeWrapper.body_of(result.raw)))
            if edge.present:
                self.ctx.store.propose_finding(
                    Finding(
                        engagement_id=self.ctx.engagement_id, asset=host,
                        type=f"web-edge:{(edge.vendor or 'unknown').lower().replace(' ', '-')}",
                        title=f"Fronted by {edge.describe()}",
                        priority=Priority.INFORMATIONAL,
                        evidence=(f"raw:{result.audit_id}",), proposed_by=self.spec.id,
                        metadata={"is_cdn": edge.is_cdn, "is_waf": edge.is_waf,
                                  "vendor": edge.vendor, "signals": list(edge.signals)},
                    ),
                    emitted_by=self.spec.id,
                )
                self._note_finding()
                _log.info("edge detected", host=host, edge=edge.describe(),
                          signals=edge.signals)
                return edge
        return EdgeProfile()

    def _has_param_surface(self, host: str) -> bool:
        """Whether any parameterised endpoint / injectable lead is known yet.

        The signal that heavyweight fuzzing (dalfox) has something to chew on —
        aggressive scanning without a lead is wasted work, especially behind a WAF.
        """

        for f in self.ctx.store.findings():
            if f.asset != host:
                continue
            if f.type.startswith(("sqli", "xss", "open-redirect")):
                return True
            if f.type.startswith("web-endpoint:") and f.metadata.get("params"):
                return True
        return False

    #: Focused, low-touch nuclei template tags for intelligence *capture* — tech
    #: fingerprinting, exposures, misconfig, known CVEs, disclosures, default
    #: logins — instead of the full corpus (kinder to a live/remote target).
    _CAPTURE_TAGS = "tech,exposure,misconfiguration,cve,disclosure,default-login,tokens"

    def _run_nuclei(self, host: str, scheme: str, port: int | None,
                    edge: EdgeProfile | None = None) -> None:
        if "nuclei" not in self.spec.tools:
            return
        args: dict[str, object] = {"scheme": scheme, "port": port}
        # Strategy: the full corpus is for an origin we can actually probe. Behind
        # a CDN/WAF the edge rate-limits templated traffic into slow timeouts and
        # answers for a shared frontend — the full corpus yields false positives
        # (the ESXi-SLP mis-fire) for real cost. So even in active mode we run the
        # FOCUSED, identity-oriented set against an edge. Not a scope restriction —
        # just the templates that can find something on this surface.
        if self.spec.guardrails.active_injection_screen and not (edge and edge.present):
            preset = "default"
        else:
            preset = "info"
            args["tags"] = self._CAPTURE_TAGS
            if edge and edge.present:
                _log.info("nuclei adapted for edge", host=host,
                          edge=edge.describe(), preset=preset)
        result = self.run_tool("nuclei", host, ToolProfile(preset=preset, args=args))
        if result is None:
            return
        for hit in result.parsed.get("results", []):
            self._ingest_hit(host, hit, result.audit_id)

    def _run_nikto(self, host: str, scheme: str, port: int | None) -> None:
        if "nikto" not in self.spec.tools:
            return
        # Nikto is a thorough but slow signature scan; capture-only intelligence
        # gathering skips it (endpoints/params/tech/leads matter more and are
        # far faster on a remote host). Full confirmation runs keep it.
        if not self.spec.guardrails.active_injection_screen:
            return
        result = self.run_tool(
            "nikto", host, ToolProfile(args={"scheme": scheme, "port": port or 80})
        )
        if result is None:
            return
        for item in result.parsed.get("results", []):
            self.ctx.store.propose_finding(
                Finding(
                    engagement_id=self.ctx.engagement_id,
                    asset=host,
                    type=f"web:nikto:{item.get('id') or 'finding'}",
                    title=item.get("message") or "Nikto finding",
                    priority=Priority.LOW,
                    evidence=(f"raw:{result.audit_id}",),
                    proposed_by=self.spec.id,
                    metadata={"url": item.get("url"), "method": item.get("method")},
                ),
                emitted_by=self.spec.id,
            )
            self._note_finding()

    def _run_wpscan(self, host: str, scheme: str, port: int | None) -> None:
        if "wpscan" not in self.spec.tools:
            return
        result = self.run_tool(
            "wpscan", host, ToolProfile(args={"scheme": scheme, "port": port})
        )
        if result is None:
            return
        for vuln in result.parsed.get("vulnerabilities", []):
            self.ctx.store.propose_finding(
                Finding(
                    engagement_id=self.ctx.engagement_id,
                    asset=host,
                    type=f"web:wpscan:{vuln.get('component', 'core')}",
                    title=vuln.get("title") or "WordPress vulnerability",
                    priority=Priority.MEDIUM,
                    evidence=(f"raw:{result.audit_id}",),
                    proposed_by=self.spec.id,
                    metadata={"references": vuln.get("references"),
                              "wp_version": result.parsed.get("version")},
                ),
                emitted_by=self.spec.id,
            )
            self._note_finding()

    def _run_katana(self, host: str, scheme: str, port: int | None,
                    edge: EdgeProfile | None = None) -> None:
        if "katana" not in self.spec.tools:
            return
        # Better leads come from a better map. In active mode — and especially in
        # front of a CDN/WAF where a plain crawl sees only the static shell — go
        # deeper and render JavaScript (headless) so SPA/Webflow routes and
        # XHR-called API endpoints become discoverable surface to attack.
        deep = self.spec.guardrails.active_injection_screen or bool(edge and edge.present)
        args: dict[str, object] = {"scheme": scheme, "port": port}
        if deep:
            args["depth"] = 3
            args["headless"] = True
        result = self.run_tool("katana", host, ToolProfile(args=args))
        if result is None:
            return
        for ep in result.parsed.get("endpoints", []):
            path = ep.get("path", "/")
            params = ep.get("params") or []
            # Capture EVERY crawled endpoint as attack-surface intel (not only the
            # parameterised ones) — the map itself is what the offensive layer uses.
            self.ctx.store.propose_finding(
                Finding(
                    engagement_id=self.ctx.engagement_id,
                    asset=host,
                    type=f"web-endpoint:{path}",
                    title=f"Crawled endpoint {path}"
                    + (f" (params: {', '.join(params)})" if params else ""),
                    priority=Priority.INFORMATIONAL,
                    evidence=(f"raw:{result.audit_id}",),
                    proposed_by=self.spec.id,
                    metadata={"scheme": scheme, "port": port, "path": path,
                              "params": list(params), "method": ep.get("method", "GET")},
                ),
                emitted_by=self.spec.id,
            )
            self._note_finding()
            # A crawled endpoint WITH parameters yields typed injection leads.
            for param in params:
                self._propose_param_candidates(
                    host, scheme, port, path, param, result.audit_id)

    def _run_dalfox(self, host: str, scheme: str, port: int | None,
                    edge: EdgeProfile | None = None) -> None:
        if "dalfox" not in self.spec.tools:
            return
        # Lead-gated escalation: dalfox is a heavyweight reflected-XSS fuzzer. On
        # a WAF/CDN edge with no parameterised surface discovered, it only ever
        # hits the timeout ceiling for zero yield (exactly the ggi run's wasted
        # 10-minute dalfox). So behind an edge we run it ONLY once a parameter
        # surface exists — and with a tight timeout regardless.
        if edge and edge.present and not self._has_param_surface(host):
            _log.info("dalfox skipped — no parameterised surface behind edge",
                      host=host, edge=edge.describe())
            self.ctx.store.record_tool_run(
                "dalfox", host, "skipped",
                "lead-gated: no parameterised surface behind CDN/WAF")
            return
        args: dict[str, object] = {"scheme": scheme, "port": port}
        profile = ToolProfile(args=args, timeout_sec=60 if edge and edge.present else None)
        result = self.run_tool("dalfox", host, profile)
        if result is None:
            return
        for finding in result.parsed.get("findings", []):
            param = finding.get("param")
            self.ctx.store.propose_finding(
                Finding(
                    engagement_id=self.ctx.engagement_id,
                    asset=host,
                    type=f"xss-reflected:{param or 'param'}",
                    title=f"Reflected XSS in {param} ({finding.get('inject_type')})",
                    priority=Priority.HIGH,
                    evidence=(f"raw:{result.audit_id}",),
                    proposed_by=self.spec.id,
                    metadata={"param": param, "method": finding.get("method", "GET")},
                ),
                emitted_by=self.spec.id,
            )
            self._note_finding()

    def _ingest_api_specs(self, host: str, scheme: str, port: int | None) -> None:
        """Fetch a served OpenAPI/Swagger spec and mine its full endpoint map.

        Read-only: fetches the common spec locations, and the first document that
        parses becomes a complete inventory of endpoints + parameters — every one
        an attack lead. Deterministic parsing of the raw body (never surfaced to
        the model), governed like any other probe.
        """

        if "http_probe" not in self.spec.tools:
            return
        for spec_path in OPENAPI_PATHS:
            try:
                result = self.run_tool("http_probe", host, ToolProfile(args={
                    "scheme": scheme, "port": port, "path": spec_path,
                    "max_bytes": 2_000_000}))
            except (RateLimitExceededError, RoEViolationError):
                return
            if result is None or result.parsed.get("status") != 200:
                continue
            ops = parse_openapi(HttpProbeWrapper.body_of(result.raw))
            if not ops:
                continue
            for op in ops:
                params = op.params
                self.ctx.store.propose_finding(
                    Finding(
                        engagement_id=self.ctx.engagement_id, asset=host,
                        type=f"web-endpoint:{op.path}",
                        title=f"API {op.method} {op.path}"
                        + (f" (params: {', '.join(params)})" if params else ""),
                        priority=Priority.INFORMATIONAL,
                        evidence=(f"raw:{result.audit_id}",), proposed_by=self.spec.id,
                        metadata={"scheme": scheme, "port": port, "path": op.path,
                                  "params": list(params), "method": op.method},
                    ),
                    emitted_by=self.spec.id,
                )
                self._note_finding()
                for param in params:
                    self._propose_param_candidates(
                        host, scheme, port, op.path, param, result.audit_id)
            _log.info("api spec ingested", host=host, spec=spec_path, operations=len(ops))
            return  # first parseable spec wins

    #: Parameter names that typically flow into a redirect (open-redirect leads).
    _REDIRECT_PARAMS = frozenset({
        "to", "url", "redirect", "redirect_uri", "redirecturl", "next", "return",
        "returnurl", "return_url", "dest", "destination", "goto", "continue",
        "callback", "forward", "out", "link",
    })

    def _propose_param_candidates(
        self, host: str, scheme: str, port: int | None, path: str, param: str,
        audit_id: str,
    ) -> None:
        """Raise the injection leads a single parameter warrants (rule #1: leads).

        Every parameter is a SQLi and a reflected-XSS candidate; redirect-shaped
        parameter names additionally raise an open-redirect candidate. Each is a
        PROPOSED lead the read-only oracles then confirm (XSS/redirect) or the
        active screen / gated path handles (SQLi).
        """

        base = {"scheme": scheme, "port": port, "path": path, "param": param}
        leads: list[tuple[str, str, dict[str, object]]] = [
            ("sqli-candidate", f"candidate SQLi at {path}?{param}=",
             {**base, "base_value": "1"}),
            ("xss-candidate", f"candidate reflected-XSS at {path}?{param}=", dict(base)),
        ]
        if param.lower() in self._REDIRECT_PARAMS:
            leads.append(("open-redirect-candidate",
                          f"candidate open-redirect at {path}?{param}=", dict(base)))
        for ftype, title, meta in leads:
            self.ctx.store.propose_finding(
                Finding(
                    engagement_id=self.ctx.engagement_id, asset=host, type=ftype,
                    title=title, priority=Priority.MEDIUM,
                    evidence=(f"raw:{audit_id}",),
                    proposed_by=self.spec.id, metadata=meta,
                ),
                emitted_by=self.spec.id,
            )
            self._note_finding()

    # --- active injection detection (read-only breachability screen) ----------

    def _detect_injections(self, host: str, scheme: str, port: int | None) -> None:
        """Screen discovered/known injection points and propose confirmable leads.

        This is *detection*, not *exploitation*: every probe is a read-only GET
        through the scope-enforced HTTP probe that observes only status/size —
        never data. A suspicious differential becomes a PROPOSED
        ``sqli-boolean-blind`` hypothesis, which the independent verification
        oracle then re-confirms rigorously (rule #1). Actual exploitation
        (SQLMap data extraction, RCE modules) stays behind the human gate.
        """

        if "http_probe" not in self.spec.tools:
            return
        # Capture-only intelligence gathering skips active probing: the injection
        # leads are still recorded (from crawling/scanning), just not confirmed.
        if not self.spec.guardrails.active_injection_screen:
            return
        points = build_injection_points(
            self.ctx.store, host, scheme, port, limit=_DETECT_LIMIT
        )
        seen = {
            (f.metadata.get("path"), f.metadata.get("param"))
            for f in self.ctx.store.findings()
            if f.type.startswith("sqli-boolean-blind")
        }
        for point in points:
            if (point.path, point.param) in seen:
                continue
            try:
                evidence = self._screen_injection(host, point)
            except (RateLimitExceededError, RoEViolationError):
                # Governance said stop probing — keep what we have, don't crash.
                _log.warning("injection screening halted by governance", host=host)
                return
            if evidence is None:
                continue
            self._propose_injection_hypothesis(host, point, evidence)
            seen.add((point.path, point.param))

    def _screen_injection(self, host: str, point: InjectionPoint) -> str | None:
        """Cheap read-only screen; returns evidence audit-id if suspicious.

        Fires on the high-precision SQL signals: an error/500 provoked by an odd
        single quote, a status flip, or a boolean true/false size differential.
        The rigorous multi-trial confirmation is the oracle's job.
        """

        base_args = {
            "scheme": point.scheme, "port": point.port,
            "path": point.path, "method": point.method,
        }

        def sig(value: str) -> tuple[int | None, int | None, str] | None:
            result = self.run_tool(
                "http_probe", host,
                ToolProfile(args={**base_args, "params": {point.param: value}}),
            )
            if result is None:
                return None
            return (result.parsed.get("status"), result.parsed.get("size"), result.audit_id)

        base = sig(point.base_value)
        if base is None or base[0] is None or base[0] == 404:
            return None  # endpoint absent/unreachable — nothing to screen
        odd = sig(point.base_value + "'")
        if odd is None or odd[0] is None:
            return None
        base_status = base[0]
        odd_status = odd[0]
        if (odd_status >= 500 and base_status < 500) or odd_status != base_status:
            return odd[2]  # SQL error or status flip on a lone quote
        # Boolean-blind: TRUE and FALSE conditions yield different response sizes.
        t = sig(point.base_value + _TRUE_SUFFIX)
        f = sig(point.base_value + _FALSE_SUFFIX)
        if t and f and t[1] is not None and f[1] is not None and t[1] != f[1]:
            return t[2]
        return None

    def _propose_injection_hypothesis(
        self, host: str, point: InjectionPoint, evidence_audit_id: str
    ) -> None:
        self.ctx.store.propose_finding(
            Finding(
                engagement_id=self.ctx.engagement_id,
                asset=host,
                type="sqli-boolean-blind",
                title=f"suspected SQLi at {point.path}?{point.param}= (screening differential)",
                priority=Priority.HIGH,
                evidence=(f"raw:{evidence_audit_id}",),
                proposed_by=self.spec.id,
                metadata={
                    "scheme": point.scheme, "port": point.port, "path": point.path,
                    "param": point.param, "base_value": point.base_value,
                    "method": point.method, "detection": "active-screen",
                },
            ),
            emitted_by=self.spec.id,
        )
        self._note_finding()
        _log.info("injection hypothesis proposed", host=host,
                  path=point.path, param=point.param)

    def _ingest_hit(self, target: str, hit: dict[str, Any], audit_id: str) -> None:
        template = hit.get("template_id") or "unknown"
        severity = (hit.get("severity") or "info").lower()
        priority = _SEVERITY_TO_PRIORITY.get(severity, Priority.INFORMATIONAL)

        self.ctx.store.propose_finding(
            Finding(
                engagement_id=self.ctx.engagement_id,
                asset=_host_of(target),
                type=f"web:{template}",
                title=hit.get("name") or template,
                priority=priority,
                evidence=(f"raw:{audit_id}",),
                proposed_by=self.spec.id,
                metadata={"matched_at": hit.get("matched_at"), "severity": severity},
            ),
            emitted_by=self.spec.id,
        )
        self._note_finding()

        # A templated SQLi signal becomes a candidate lead for the confirmer.
        blob = f"{template} {hit.get('name', '')} {hit.get('type', '')}".lower()
        if any(h in blob for h in _SQLI_HINTS):
            self._propose_sqli_candidate(target, hit, audit_id)

    def _propose_sqli_candidate(
        self, target: str, hit: dict[str, Any], audit_id: str
    ) -> None:
        matched_at = hit.get("matched_at") or ""
        parts = urlsplit(matched_at)
        params = parse_qs(parts.query)
        param = next(iter(params), None)
        base_value = params.get(param, ["1"])[0] if param else "1"
        if param is None:
            return  # no injectable parameter to point the confirmer at
        self.ctx.store.propose_finding(
            Finding(
                engagement_id=self.ctx.engagement_id,
                asset=_host_of(target),
                type="sqli-candidate",
                title=f"candidate SQLi at {parts.path}?{param}=",
                priority=Priority.MEDIUM,
                evidence=(f"raw:{audit_id}",),
                proposed_by=self.spec.id,
                metadata={
                    "scheme": parts.scheme or "http",
                    "port": parts.port,
                    "path": parts.path or "/",
                    "param": param,
                    "base_value": base_value,
                },
            ),
            emitted_by=self.spec.id,
        )
        self._note_finding()
        _log.info("sqli candidate proposed", target=target, path=parts.path, param=param)


def _header_block(raw: bytes) -> str:
    """The HTTP response header text from a ``-i`` probe body (headers + body).

    curl ``-i`` prints headers, a blank line, then the body. We isolate the
    header block so edge fingerprinting never keys off a coincidental token in
    page content. Bounded so a huge body can't blow up the scan.
    """

    head, _, _ = raw.partition(b"\r\n\r\n")
    if not head:
        head, _, _ = raw.partition(b"\n\n")
    return head[:8192].decode("latin-1", errors="replace")


def _host_of(target: str) -> str:
    """Reduce a URL target to its bare host (assets are keyed by host/IP)."""

    if "://" in target:
        return urlsplit(target).hostname or target
    return target


def _split_target(target: str) -> tuple[str, str, int | None]:
    """Split a URL or bare host into (host, scheme, port)."""

    if "://" in target:
        parts = urlsplit(target)
        return parts.hostname or target, parts.scheme or "http", parts.port
    return target, "http", None
