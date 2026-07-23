"""Web specialist on the reasoning loop (Phase D — web depth).

The analogue of the Recon specialist (A4), one layer deeper into the kill chain.
Where Recon turned ports/paths into *where to look*, the Web specialist turns web
tool output into *what is likely wrong and how to prove it*: each crawled
parameter, Nuclei hit, reflected-XSS point, or SQLi signal becomes a ranked
:class:`~attack_engine.schemas.beliefs.Hypothesis` about a concrete
vulnerability class at a concrete injection point.

That is the "web recon → proof" chain the platform is built on:

    tool output → :class:`WebObserver` → oracle-ready hypotheses
                → :class:`WebGraduator` → PROPOSED Findings → Phase-B oracles confirm

The specialist only ever *proposes* (rule #1). A hypothesis never becomes truth
here — the :class:`WebGraduator` graduates the oracle-testable ones into
*proposed* Findings, and a deterministic Phase-B impact oracle (LFI file-read,
SSRF-via-OOB, boolean-blind SQLi, reflected-XSS, open-redirect) is what actually
confirms them. Everything flows through the Tool Runner boundary via
:class:`~attack_engine.agents.tool_actor.ToolRunnerActor`, so scope/rate/RoE hold.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import parse_qsl, urlsplit

from ..knowledge.store import KnowledgeStore
from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from ..schemas.beliefs import Hypothesis, Observation
from ..schemas.findings import Finding
from ..schemas.tools import ToolResult
from ..verify.oracles import OracleRegistry, default_oracle_registry
from .actions import ActionOutcome, ProposedAction
from .context import AgentContext
from .payload_synth import PayloadSynthesizer
from .reasoning import LlmPlanner, LoopContext, ReasoningLoop
from .tool_actor import ToolRunnerActor

_log = get_logger("agent.web")

#: Web tools this specialist may reach for (must map to real wrappers).
DEFAULT_WEB_TOOLS: tuple[str, ...] = ("katana", "nuclei", "dalfox", "sqlmap")

#: Upper bound on parameterised endpoints turned into candidates per crawl —
#: a safety cap on belief volume (a deep crawl can surface hundreds of params).
_CANDIDATE_LIMIT = 40

# --- vulnerability-class inference ------------------------------------------

#: Parameter-name fragments that raise a specific class as the *likely* one.
#: (SQLi and reflected-XSS are near-universal for user-controlled input, so they
#: are considered for every parameter rather than gated on a name.)
_LFI_PARAMS = ("file", "path", "page", "doc", "document", "folder", "load",
               "include", "template", "view", "read", "download", "filename")
_SSRF_PARAMS = ("url", "uri", "link", "redirect", "next", "dest", "destination",
                "return", "returnurl", "continue", "callback", "target", "site",
                "host", "domain", "feed", "proxy", "fetch", "image")
_IDOR_PARAMS = ("id", "uid", "userid", "account", "acct", "order", "num", "pid",
                "gid", "ref", "key", "no")
_XSS_PARAMS = ("q", "s", "search", "query", "name", "keyword", "message",
               "comment", "title", "text", "content", "lang")
_SSTI_PARAMS = ("template", "tpl", "name", "greeting", "message", "preview",
                "render", "email", "subject", "body", "content")
_CMDI_PARAMS = ("cmd", "command", "exec", "host", "ip", "ping", "dns", "lookup",
                "target", "addr", "domain", "func", "run", "shell", "system")

#: Hypothesis kind → the Finding type an oracle can confirm. A kind absent here
#: (``cve``, ``web-vuln``, ``idor`` — no oracle yet) never graduates; it stays a
#: live lead. This map is the single source of truth for "oracle-ready".
_CLASS_TO_FINDING_TYPE: dict[str, str] = {
    "sqli": "sqli-boolean-blind",
    "xss": "xss-reflected",
    "lfi": "lfi",
    "ssrf": "ssrf",
    "open-redirect": "open-redirect",
    "ssti": "ssti",
    "cmdi": "command-injection",
    # NOTE: `idor`/broken-authz is intentionally NOT auto-graduated yet. The
    # AccessControlOracle can confirm it, but only given an authorized-baseline
    # credential — autonomous credential/session handling is a later Phase-D
    # slice. Until then IDOR stays a live lead rather than an unprovable Finding.
}

#: Classes whose oracle needs an injection *parameter* (path-based LFI does not).
_REQUIRES_PARAM = frozenset({"sqli", "xss", "ssrf", "open-redirect", "ssti", "cmdi"})

#: Which tool most cheaply tests each class — a hint for the planner only.
_TOOLS_BY_CLASS: dict[str, tuple[str, ...]] = {
    "sqli": ("sqlmap",),
    "xss": ("dalfox",),
    "lfi": ("nuclei", "http_probe"),
    "ssrf": ("nuclei", "http_probe"),
    "open-redirect": ("http_probe",),
    "ssti": ("nuclei", "http_probe"),
    "cmdi": ("nuclei", "http_probe"),
    "idor": ("http_probe",),
}

#: Starting prior per class (belief is earned; specific-smelling params start higher).
_PRIOR_BY_CLASS: dict[str, float] = {
    "sqli": 0.3, "xss": 0.3, "lfi": 0.35, "ssrf": 0.4,
    "open-redirect": 0.3, "ssti": 0.35, "cmdi": 0.4, "idor": 0.4,
}

WEB_SYSTEM_PROMPT = (
    "You are the Web-exploitation specialist of an authorized red-team "
    "engagement. Given an in-scope web surface, you build an understanding of "
    "the app (endpoints, parameters, auth) and reason about which modern "
    "vulnerability classes each injection point is likely to hold — SQLi, "
    "reflected XSS, LFI/path-traversal, SSRF, open-redirect, IDOR. Crawl to "
    "discover parameters, run templated and targeted checks, and prefer the "
    "cheapest probe that most reduces uncertainty about a real, provable flaw. "
    "You only observe and propose — you never claim a weakness is real; the "
    "confirmation oracles prove it. Propose the ranked next actions as tool "
    "calls against in-scope targets."
)


def _matches(name: str, hints: tuple[str, ...]) -> bool:
    """Whether a param name matches a class hint without spurious substrings.

    Short hints (``id``, ``no``) match only as whole tokens so ``id`` does not
    fire on ``video``; longer hints (``file``) may match as a substring.
    """

    return any(
        name == h
        or name.endswith(("_" + h, "-" + h))
        or name.startswith((h + "_", h + "-"))
        or (len(h) >= 4 and h in name)
        for h in hints
    )


def _param_classes(param: str) -> tuple[str, ...]:
    """Vulnerability classes a single parameter is a candidate for."""

    name = param.lower()
    classes: list[str] = ["sqli"]  # any user-controlled param is a SQLi candidate
    if _matches(name, _LFI_PARAMS):
        classes.append("lfi")
    if _matches(name, _SSRF_PARAMS):
        classes.append("ssrf")
        classes.append("open-redirect")
    if _matches(name, _IDOR_PARAMS):
        classes.append("idor")
    if _matches(name, _XSS_PARAMS):
        classes.append("xss")
    if _matches(name, _SSTI_PARAMS):
        classes.append("ssti")
    if _matches(name, _CMDI_PARAMS):
        classes.append("cmdi")
    return tuple(dict.fromkeys(classes))


#: Substrings in a Nuclei template id/name → the class it evidences.
_NUCLEI_NEEDLES: tuple[tuple[str, str], ...] = (
    ("sqli", "sqli"), ("sql-injection", "sqli"), ("sql_injection", "sqli"),
    ("ssrf", "ssrf"),
    ("lfi", "lfi"), ("traversal", "lfi"), ("file-read", "lfi"), ("file-inclusion", "lfi"),
    ("open-redirect", "open-redirect"), ("redirect", "open-redirect"),
    ("xss", "xss"), ("cross-site-scripting", "xss"),
    ("ssti", "ssti"), ("template-injection", "ssti"), ("template-inj", "ssti"),
    ("command-injection", "cmdi"), ("cmd-injection", "cmdi"), ("rce", "cmdi"),
    ("remote-code", "cmdi"),
)


def _classify_nuclei(template_id: str, name: str) -> str:
    """Best-effort map of a Nuclei hit to a class; ``cve``/``web-vuln`` otherwise."""

    text = f"{template_id} {name}".lower()
    for needle, cls in _NUCLEI_NEEDLES:
        if needle in text:
            return cls
    if template_id.lower().startswith("cve-"):
        return "cve"
    return "web-vuln"


def _nuclei_signal(severity: str) -> float:
    """A confirmed template match is strong evidence; scale by severity."""

    return {"critical": 0.8, "high": 0.75, "medium": 0.6, "low": 0.5}.get(severity, 0.5)


# --- URL / injection-point helpers ------------------------------------------


def _split_url(url: str) -> tuple[str, str, int | None, str] | None:
    """(scheme, host, port, path) for an absolute URL, else ``None``."""

    if "://" not in url:
        return None
    parts = urlsplit(url)
    if not parts.hostname:
        return None
    return parts.scheme or "http", parts.hostname, parts.port, parts.path or "/"


def _injection_point(scheme: str, host: str, port: int | None, path: str, param: str) -> str:
    """Canonical subject string uniquely identifying one (endpoint, param).

    Round-trippable by :func:`_parse_injection_point`, so the graduator can
    rebuild oracle metadata from the belief alone — no side state to carry.
    """

    base = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}?{param}"


def _parse_injection_point(subject: str) -> tuple[str, str, int | None, str, str | None] | None:
    """(host, scheme, port, path, param) parsed back out of a subject URL."""

    if "://" not in subject:
        return None
    parts = urlsplit(subject)
    if not parts.hostname:
        return None
    params = [p.split("=", 1)[0] for p in parts.query.split("&") if p]
    return (
        parts.hostname,
        parts.scheme or "http",
        parts.port,
        parts.path or "/",
        params[0] if params else None,
    )


class WebObserver:
    """Folds web tool output into the world model as oracle-ready hypotheses.

    Each tool contributes what it is good at: Katana discovers *parameters*
    (candidate injection points), Nuclei contributes *class evidence*, and
    Dalfox/sqlmap contribute *strong confirmations of a specific class*. Agreeing
    signals on the same injection point fuse into one belief with rising
    confidence (Bayesian fusion in the world model).
    """

    def observe(self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext) -> None:
        result = outcome.raw
        if not outcome.ok or not isinstance(result, ToolResult):
            return
        wm = ctx.world_model
        if action.tool == "katana":
            self._ingest_endpoints(wm, result)
        elif action.tool == "nuclei":
            self._ingest_nuclei(wm, result)
        elif action.tool == "dalfox":
            self._ingest_dalfox(wm, result)
        elif action.tool == "sqlmap":
            self._ingest_sqlmap(wm, result)

    # --- per-tool ingestion ---------------------------------------------------

    def _ingest_endpoints(self, wm: WorldModel, result: ToolResult) -> None:
        """Katana: each parameterised endpoint → candidates per suspected class.

        Two injection surfaces are folded in: GET query parameters (``params``)
        and POST/PUT **form fields** (``form``, surfaced by katana ``-fx -aff``).
        A form field is exactly where a command-injection point hides — e.g.
        Mutillidae's dns-lookup ``target_host`` reaches a shell — so each field
        becomes a candidate whose companion fields + the endpoint's own query
        ride as the fixed request context the oracle needs to submit the form.
        """

        endpoints = result.parsed.get("endpoints", [])
        # A form field that reaches a shell IS the web foothold, so process POST/PUT
        # forms before GET query params — otherwise a flood of crawled GET endpoints
        # could exhaust the candidate budget before the cmdi form is ever reached
        # (a deep crawl surfaces thousands of endpoints; the foothold point is rare).
        forms = [e for e in endpoints if str(e.get("method") or "GET").upper() in ("POST", "PUT")]
        others = [e for e in endpoints if e not in forms]

        seen = 0
        for ep in forms:
            url = ep.get("url")
            loc = _split_url(url) if url else None
            if loc is None:
                continue
            scheme, host, port, path = loc
            method = str(ep.get("method") or "GET").upper()
            query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            form = ep.get("form") or {}
            for pname in form:
                if seen >= _CANDIDATE_LIMIT:
                    return
                seen += 1
                # Companion fields (everything but the one being injected) plus the
                # endpoint query are the fixed context the oracle replays so the
                # form actually submits.
                data = {k: v for k, v in form.items() if k != pname}
                context: dict[str, object] = {"method": method}
                if query:
                    context["params"] = query
                if data:
                    context["data"] = data
                self._propose_param(
                    wm, scheme, host, port, path, pname,
                    source="katana", audit_id=result.audit_id,
                    surface=f"{method} form", context=context,
                )

        for ep in others:
            url = ep.get("url")
            loc = _split_url(url) if url else None
            if loc is None:
                continue
            scheme, host, port, path = loc
            for pname in ep.get("params") or []:
                if seen >= _CANDIDATE_LIMIT:
                    return
                seen += 1
                self._propose_param(
                    wm, scheme, host, port, path, pname,
                    source="katana", audit_id=result.audit_id, surface="endpoint",
                )

    def _propose_param(
        self,
        wm: WorldModel,
        scheme: str,
        host: str,
        port: int | None,
        path: str,
        pname: str,
        *,
        source: str,
        audit_id: str,
        surface: str,
        context: dict[str, object] | None = None,
    ) -> None:
        """Raise one candidate hypothesis per suspected class for a parameter."""

        subject = _injection_point(scheme, host, port, path, pname)
        for cls in _param_classes(pname):
            self._add(
                wm,
                subject=subject,
                kind=cls,
                title=f"{cls} candidate at {path}?{pname}",
                rationale=(
                    f"Parameter {pname!r} on a crawled {surface} is a "
                    f"{cls} injection candidate."
                ),
                prior=_PRIOR_BY_CLASS.get(cls, 0.3),
                probability=0.5,
                source=source,
                audit_id=audit_id,
                suggested_tools=_TOOLS_BY_CLASS.get(cls, ()),
                context=context,
            )

    def _ingest_nuclei(self, wm: WorldModel, result: ToolResult) -> None:
        """Nuclei: a template match is class evidence at its matched-at URL."""

        for hit in result.parsed.get("results", []):
            subject = hit.get("matched_at")
            if not subject:
                continue
            template_id = str(hit.get("template_id") or "")
            name = str(hit.get("name") or "")
            severity = str(hit.get("severity") or "").lower()
            cls = _classify_nuclei(template_id, name)
            self._add(
                wm,
                subject=subject,
                kind=cls,
                title=name or f"{cls} detected",
                rationale=f"Nuclei template {template_id!r} flagged {cls} ({severity or 'n/a'}).",
                prior=_PRIOR_BY_CLASS.get(cls, 0.45),
                probability=_nuclei_signal(severity),
                source="nuclei",
                audit_id=result.audit_id,
                suggested_tools=_TOOLS_BY_CLASS.get(cls, ()),
            )

    def _ingest_dalfox(self, wm: WorldModel, result: ToolResult) -> None:
        """Dalfox: a reflected point is a strong XSS signal at its param."""

        loc = _split_url(result.target)
        for f in result.parsed.get("findings", []):
            param = f.get("param")
            if not param or loc is None:
                continue
            scheme, host, port, path = loc
            self._add(
                wm,
                subject=_injection_point(scheme, host, port, path, str(param)),
                kind="xss",
                title=f"Reflected XSS at {path}?{param}",
                rationale=(
                    f"Dalfox reflected a probe payload in param {param!r} "
                    f"({f.get('inject_type')})."
                ),
                prior=0.5,
                probability=0.8,
                source="dalfox",
                audit_id=result.audit_id,
                suggested_tools=("dalfox",),
            )

    def _ingest_sqlmap(self, wm: WorldModel, result: ToolResult) -> None:
        """sqlmap: an injectable verdict is a strong SQLi signal at its param."""

        parsed = result.parsed
        param = parsed.get("parameter")
        loc = _split_url(result.target)
        if not parsed.get("injectable") or not param or loc is None:
            return
        scheme, host, port, path = loc
        self._add(
            wm,
            subject=_injection_point(scheme, host, port, path, str(param)),
            kind="sqli",
            title=f"SQL injection at {path}?{param}",
            rationale=f"sqlmap reports param {param!r} injectable ({parsed.get('technique')}).",
            prior=0.5,
            probability=0.9,
            source="sqlmap",
            audit_id=result.audit_id,
            suggested_tools=("sqlmap",),
        )

    # --- helper ---------------------------------------------------------------

    @staticmethod
    def _add(
        wm: WorldModel,
        *,
        subject: str,
        kind: str,
        title: str,
        rationale: str,
        prior: float,
        probability: float,
        source: str,
        audit_id: str,
        suggested_tools: tuple[str, ...],
        context: dict[str, object] | None = None,
    ) -> None:
        """Add a lead, or reinforce an existing one, avoiding duplicates."""

        existing = wm.find_hypothesis(kind=kind, subject=subject)
        obs = Observation(source=source, probability=probability, note=f"raw:{audit_id}")
        if existing is not None:
            wm.observe(existing.id, obs)
            return
        wm.add_hypothesis(
            subject=subject,
            kind=kind,
            title=title,
            rationale=rationale,
            prior=prior,
            suggested_tools=suggested_tools,
            created_by="web",
            observations=(obs,),
            context=context,
        )


class WebGraduator:
    """Graduates oracle-testable web hypotheses into PROPOSED Findings.

    This is the seam from proposal-space (beliefs) into the confirmation pipeline
    (rule #1): a hypothesis never becomes truth here — it becomes a *proposed*
    Finding carrying the metadata a Phase-B oracle needs (param/path/scheme/port).
    Only hypotheses whose class maps to a **registered oracle** graduate; the rest
    (CVE leads, IDOR without an authz oracle yet) stay live leads. Graduation is
    idempotent — a graduated hypothesis is linked to its Finding and no longer
    returned by :meth:`WorldModel.open_hypotheses`.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        *,
        registry: OracleRegistry | None = None,
        synthesizer: PayloadSynthesizer | None = None,
        created_by: str = "web",
    ) -> None:
        self._store = store
        self._registry = registry or default_oracle_registry()
        self._synthesizer = synthesizer
        self._created_by = created_by

    def graduate(self, wm: WorldModel, *, min_confidence: float = 0.5) -> list[Finding]:
        """Promote every confident, oracle-ready lead into a proposed Finding.

        When a :class:`PayloadSynthesizer` is wired, LFI/SQLi findings are enriched
        with context-aware proof payloads before proposal (the model proposes; the
        synthesizer's deterministic gate + the oracle dispose).
        """

        graduated: list[Finding] = []
        for h in wm.open_hypotheses():
            if h.confidence < min_confidence:
                continue
            finding = self._to_finding(h)
            if finding is None or self._registry.for_finding(finding) is None:
                continue  # not oracle-ready → leave it a lead
            if self._synthesizer is not None:
                finding = self._synthesizer.enrich(finding)
            stored = self._store.propose_finding(finding, emitted_by=self._created_by)
            wm.link_finding(h.id, stored.id)
            graduated.append(stored)
            _log.debug("hypothesis graduated", hypothesis=h.id, finding=stored.id, type=stored.type)
        return graduated

    def _to_finding(self, h: Hypothesis) -> Finding | None:
        ftype = _CLASS_TO_FINDING_TYPE.get(h.kind)
        if ftype is None:
            return None
        loc = _parse_injection_point(h.subject)
        if loc is None:
            return None
        host, scheme, port, path, param = loc
        if param is None and h.kind in _REQUIRES_PARAM:
            return None
        metadata: dict[str, object] = {"scheme": scheme, "path": path or "/", "method": "GET"}
        if port is not None:
            metadata["port"] = port
        if param is not None:
            metadata["param"] = param
        # Fold in oracle context the subject URL cannot encode (a POST form's
        # method + fixed companion fields). This is what lets the oracle submit a
        # command-injection form rather than only a GET query point.
        for key in ("method", "params", "data", "base_value"):
            if key in h.context:
                metadata[key] = h.context[key]
        return Finding(
            engagement_id=self._store.engagement_id,
            asset=host,
            type=ftype,
            title=h.title,
            description=h.rationale,
            metadata=metadata,
            proposed_by=self._created_by,
            evidence=tuple(o.note for o in h.observations if o.note),
        )


class _ObserveAndGraduate:
    """Observer that folds web output into beliefs AND graduates the oracle-ready
    ones into PROPOSED findings each step — the autonomous "recon → proof" seam.

    Without this the loop only accumulates beliefs; graduation had to be called by
    hand, so a fully-autonomous run never produced findings for the oracles to
    confirm. Graduation is idempotent (a graduated hypothesis is linked and no
    longer re-graduated), so running it every step is safe and cheap.
    """

    def __init__(
        self, observer: WebObserver, graduator: WebGraduator, *, min_confidence: float = 0.5
    ) -> None:
        self._observer = observer
        self._graduator = graduator
        self._min_confidence = min_confidence

    def observe(self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext) -> None:
        self._observer.observe(action, outcome, ctx)
        self._graduator.graduate(ctx.world_model, min_confidence=self._min_confidence)


def build_web_loop(
    ctx: AgentContext,
    *,
    tools: Sequence[str] | None = None,
    tier: ModelTier = ModelTier.FRONTIER,
    max_steps: int = 20,
    graduate: bool = True,
) -> ReasoningLoop:
    """Assemble the Web specialist's reasoning loop from an engagement's services.

    The loop plans with the model gateway, acts through the Tool Runner, observes
    web output into the world model as oracle-ready hypotheses, and (by default)
    graduates the confident, oracle-backed ones into PROPOSED Findings each step —
    so a caller's :meth:`Engagement.verify` can then confirm them. Drive it toward
    a goal with the
    :class:`~attack_engine.orchestrator.controller.ObjectiveController`.
    """

    if ctx.gateway is None:
        raise ValueError("web loop requires a model gateway in the AgentContext")
    planner = LlmPlanner(
        ctx.gateway,
        tools=list(tools or DEFAULT_WEB_TOOLS),
        system_prompt=WEB_SYSTEM_PROMPT,
        tier=tier,
        actor_name="web",
        engagement_id=ctx.engagement_id,
    )
    observer: WebObserver | _ObserveAndGraduate = WebObserver()
    if graduate:
        graduator = WebGraduator(
            ctx.store,
            synthesizer=PayloadSynthesizer(ctx.gateway, engagement_id=ctx.engagement_id),
        )
        observer = _ObserveAndGraduate(WebObserver(), graduator)
    return ReasoningLoop(
        planner,
        ToolRunnerActor(ctx.tool_runner),
        observer,
        max_steps=max_steps,
    )
