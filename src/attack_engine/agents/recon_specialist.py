"""Recon specialist on the reasoning loop (spec §2/§4) — the first real agent
to think instead of follow a script.

The old SurfaceMapper drove nmap→httpx→ffuf in a fixed order. This specialist
reuses the same tool wrappers but lets a model *decide* the next probe from the
world model, and — the important part — turns each tool result into **beliefs**:
discovered assets land in the knowledge store, and each interesting service or
path becomes a ranked :class:`Hypothesis` the planner reasons over next. That is
what makes the run adaptive: find port 3000 → hypothesize a web app → decide to
enumerate it.

Everything still flows through the Tool Runner boundary (via
:class:`~attack_engine.agents.tool_actor.ToolRunnerActor`) and the specialist
only ever *proposes* — confirmation stays with the oracles (rule #1).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from ..schemas.beliefs import Observation
from ..schemas.findings import Asset, Finding, Priority, Service
from ..schemas.tools import ToolResult
from .actions import ActionOutcome, ProposedAction
from .context import AgentContext
from .reasoning import LlmPlanner, LoopContext, ReasoningLoop
from .tool_actor import ToolRunnerActor

_log = get_logger("agent.recon")

#: Recon tools this specialist may reach for (must map to real wrappers).
DEFAULT_RECON_TOOLS: tuple[str, ...] = ("nmap", "masscan", "httpx", "ffuf", "kube_hunter")

#: Ports we treat as web surface worth enumerating.
_WEB_PORTS: dict[int, str] = {80: "http", 8080: "http", 8000: "http", 3000: "http",
                              443: "https", 8443: "https"}

#: Kubernetes control-plane ports — an exposed one is a high-value pivot into a
#: container cluster, so a hit routes to the kube_hunter probe.
_K8S_PORTS: dict[int, str] = {6443: "kubernetes-api", 8443: "kubernetes-api",
                              10250: "kubelet", 10255: "kubelet-readonly",
                              2379: "etcd"}

#: Path fragments that smell like something an attacker wants (raises a lead's prior).
_SENSITIVE_PATHS = ("admin", "login", "config", "backup", ".git", "api", "upload", "debug")

RECON_SYSTEM_PROMPT = (
    "You are the Recon specialist of an authorized red-team engagement. You map "
    "an in-scope target's attack surface and surface promising leads for the rest "
    "of the fleet. Think like an operator: expand the surface before committing, "
    "follow web ports with content discovery, and prefer the cheapest probe that "
    "most reduces uncertainty about how the target could be breached. You only "
    "observe — you never exploit, and you never claim a weakness is real; you "
    "raise it as a lead for the confirmation oracles. Propose the ranked next "
    "actions as tool calls against in-scope targets.\n\n"
    "Modern targets frequently run container orchestration. For each in-scope "
    "host, also run 'kube_hunter' (target = the bare host) to detect an exposed "
    "Kubernetes control plane — the API server (:6443), kubelet (:10250) or etcd "
    "(:2379). These high ports are missed by a default port scan, so probe for "
    "them explicitly; an exposed k8s plane is a high-value lead.\n\n"
    "IMPORTANT tool-call format: the 'target' MUST be a bare host or IP (e.g. "
    "'10.5.0.12') — scope is validated on the host/IP, so a full URL is refused. "
    "For a web probe, keep the bare host as target and put the scheme/port in "
    "params, e.g. {\"scheme\": \"http\", \"port\": 80}."
)


class ReconObserver:
    """Folds recon tool output into the world model as assets + hypotheses.

    This is the 'think like a hacker' step: raw ports/paths become beliefs about
    where the target is weak, each with a confidence the loop can act on.
    """

    def observe(self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext) -> None:
        result = outcome.raw
        if not outcome.ok or not isinstance(result, ToolResult):
            return
        wm = ctx.world_model
        if action.tool in ("nmap", "masscan"):
            self._ingest_ports(wm, result)
        elif action.tool == "httpx":
            self._ingest_http(wm, result)
        elif action.tool == "ffuf":
            self._ingest_paths(wm, result)
        elif action.tool == "kube_hunter":
            self._ingest_k8s(wm, result)

    # --- per-tool ingestion ---------------------------------------------------

    def _ingest_ports(self, wm: WorldModel, result: ToolResult) -> None:
        ports: list[dict[str, Any]] = result.parsed.get("ports", [])
        address = result.target
        services = tuple(
            Service(
                port=int(p["port"]),
                protocol=p.get("protocol", "tcp"),
                name=p.get("service"),
                product=p.get("product"),
                version=p.get("version"),
            )
            for p in ports
        )
        if wm.store is not None:
            wm.store.add_asset(
                Asset(address=address, services=services, engagement_id=wm.engagement_id),
                emitted_by="recon",
            )
        for svc in services:
            self._service_hypotheses(wm, address, svc, result.audit_id)

    def _service_hypotheses(
        self, wm: WorldModel, address: str, svc: Service, audit_id: str
    ) -> None:
        # A versioned product is a concrete CVE lead.
        if svc.product and svc.version:
            self._add(
                wm,
                subject=address,
                kind="cve",
                title=f"{svc.product} {svc.version} on :{svc.port} may have known CVEs",
                rationale="A precise product/version is a direct CVE-correlation lead.",
                prior=0.45,
                probability=0.6,
                source="nmap",
                audit_id=audit_id,
                suggested_tools=("searchsploit", "nuclei"),
            )
        # A web port is a surface to enumerate.
        scheme = _WEB_PORTS.get(svc.port)
        if scheme is not None:
            self._add(
                wm,
                subject=f"{scheme}://{address}:{svc.port}",
                kind="web-surface",
                title=f"Web service on {address}:{svc.port} to enumerate",
                rationale="Web surfaces are the richest source of exploitable flaws.",
                prior=0.4,
                probability=0.55,
                source="nmap",
                audit_id=audit_id,
                suggested_tools=("httpx", "ffuf", "katana"),
            )
        # A Kubernetes control-plane port is a pivot into the cluster — probe it.
        k8s = _K8S_PORTS.get(svc.port)
        if k8s is not None:
            self._add(
                wm,
                subject=address,
                kind="kubernetes",
                title=f"{k8s} on {address}:{svc.port} — probe for Kubernetes exposure",
                rationale="An exposed Kubernetes API/kubelet is a high-value pivot into the cluster.",
                prior=0.5,
                probability=0.6,
                source="nmap",
                audit_id=audit_id,
                suggested_tools=("kube_hunter",),
            )

    def _ingest_http(self, wm: WorldModel, result: ToolResult) -> None:
        for hit in result.parsed.get("results", []):
            server = hit.get("webserver")
            if not server:
                continue
            tech = ", ".join(hit.get("tech", []))
            self._add(
                wm,
                subject=result.target,
                kind="web-tech",
                title=f"{server} ({tech})".strip(),
                rationale="Identified stack narrows which exploit classes apply.",
                prior=0.35,
                probability=0.55,
                source="httpx",
                audit_id=result.audit_id,
                suggested_tools=("nuclei", "nikto"),
            )

    def _ingest_paths(self, wm: WorldModel, result: ToolResult) -> None:
        for hit in result.parsed.get("results", []):
            path = hit.get("path")
            if not path:
                continue
            sensitive = any(frag in path.lower() for frag in _SENSITIVE_PATHS)
            self._add(
                wm,
                subject=f"{result.target}/{path}",
                kind="exposure" if sensitive else "web-path",
                title=f"Discovered /{path} ({hit.get('status')})",
                rationale=(
                    "Sensitive path exposed without obvious auth."
                    if sensitive
                    else "Reachable path worth probing for logic/auth flaws."
                ),
                prior=0.55 if sensitive else 0.3,
                probability=0.65 if sensitive else 0.5,
                source="ffuf",
                audit_id=result.audit_id,
                suggested_tools=("katana", "dalfox"),
            )

    def _ingest_k8s(self, wm: WorldModel, result: ToolResult) -> None:
        """Fold a kube-hunter result into an exposure finding + a k8s lead.

        Recognising the cluster is itself the deliverable: a reachable API server
        / kubelet is proposed as a HIGH exposure finding, and each concrete
        kube-hunter weakness becomes its own finding. Confirmation (anonymous
        access, RCE) stays with the oracles — we only propose.
        """

        if wm.store is None:
            return
        p = result.parsed
        host = p.get("host") or result.target
        services = p.get("services") or []
        nodes = p.get("nodes") or []
        vulns = p.get("vulnerabilities") or []
        if not (services or nodes):
            return  # kube-hunter reached nothing k8s-shaped

        svc_desc = ", ".join(
            f"{s.get('service')} ({s.get('location')})" for s in services
        ) or "Kubernetes control-plane services"
        node_desc = ", ".join(str(n.get("type", "Node")) for n in nodes) or "Kubernetes node"

        wm.store.propose_finding(
            Finding(
                engagement_id=wm.engagement_id,
                asset=host,
                service="kubernetes",
                type="k8s-control-plane-exposed",
                title="Kubernetes control plane exposed to the network",
                description=(
                    f"kube-hunter identified an exposed Kubernetes control plane on "
                    f"{host} ({node_desc}). Reachable services: {svc_desc}. The API "
                    "server and/or kubelet answer from outside the cluster network, "
                    "which enlarges the attack surface — a kubelet/API misconfiguration "
                    "or a leaked credential here can lead to full cluster takeover."
                ),
                priority=Priority.HIGH,
                exploit_prob=0.4,
                evidence=(result.audit_id,),
                proposed_by="kube_hunter",
                metadata={
                    "source": "kube_hunter",
                    "k8s_nodes": nodes,
                    "k8s_services": services,
                    "remediation": (
                        "Do not expose the Kubernetes API (6443) or kubelet (10250) to "
                        "untrusted networks. Restrict them to the control plane and "
                        "trusted CIDRs with network policy / security groups, keep "
                        "kubelet anonymous auth disabled (--anonymous-auth=false) with "
                        "RBAC/Node authorization, and place the API server behind a "
                        "bastion or VPN rather than a public endpoint."
                    ),
                },
            ),
            emitted_by="recon",
        )

        for v in vulns:
            vid = str(v.get("vid") or v.get("category") or "issue").lower()
            wm.store.propose_finding(
                Finding(
                    engagement_id=wm.engagement_id,
                    asset=host,
                    service="kubernetes",
                    type=f"k8s-{vid}",
                    title=v.get("vulnerability") or v.get("category") or "Kubernetes weakness",
                    description=v.get("description") or "",
                    priority=self._k8s_priority(v.get("severity")),
                    exploit_prob=0.5,
                    evidence=(result.audit_id,),
                    proposed_by="kube_hunter",
                    metadata={
                        "source": "kube_hunter",
                        "hunter": v.get("hunter"),
                        "k8s_evidence": v.get("evidence"),
                        "avd_reference": v.get("avd_reference"),
                    },
                ),
                emitted_by="recon",
            )

        self._add(
            wm,
            subject=host,
            kind="kubernetes",
            title=f"Kubernetes control plane on {host} ({svc_desc})",
            rationale="An exposed k8s API/kubelet is a high-value pivot into the cluster.",
            prior=0.6,
            probability=0.7,
            source="kube_hunter",
            audit_id=result.audit_id,
            suggested_tools=("kube_hunter",),
        )

    @staticmethod
    def _k8s_priority(severity: Any) -> Priority:
        return {
            "high": Priority.HIGH,
            "medium": Priority.MEDIUM,
            "low": Priority.LOW,
        }.get(str(severity).lower(), Priority.MEDIUM)

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
            created_by="recon",
            observations=(obs,),
        )


def _bare_host(target: str) -> str:
    """Normalise an asset address to a bare host/IP for a host-scoped probe."""

    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]  # drop path or CIDR suffix
    if t.count(":") == 1:  # host:port (leave IPv6 literals alone)
        t = t.split(":", 1)[0]
    return t


def _recon_seed_actions(wm: WorldModel) -> list[ProposedAction]:
    """Deterministic infra probes run at recon start: kube_hunter per in-scope host.

    A default port scan misses the Kubernetes control-plane ports (:6443/:10250/
    :2379) and the LLM planner may converge before probing them, so we always run
    the container-orchestration probe once per host. Skipped for a host that
    already has a ``kubernetes`` lead, so it does not re-run every round.
    """

    if wm.store is None:
        return []
    actions: list[ProposedAction] = []
    seen: set[str] = set()
    for asset in wm.store.assets():
        host = _bare_host(asset.address)
        if not host or host in seen:
            continue
        seen.add(host)
        if wm.find_hypothesis(kind="kubernetes", subject=host) is not None:
            continue
        actions.append(
            ProposedAction(
                tool="kube_hunter",
                target=host,
                params={},
                rationale=(
                    "Infra recon: probe for an exposed Kubernetes control plane "
                    "(API/kubelet/etcd ports a default scan misses)."
                ),
                expected_value=0.6,
            )
        )
    return actions


def build_recon_loop(
    ctx: AgentContext,
    *,
    tools: Sequence[str] | None = None,
    tier: ModelTier = ModelTier.FRONTIER,
    max_steps: int = 20,
) -> ReasoningLoop:
    """Assemble the Recon reasoning loop from an engagement's services.

    The loop plans with the model gateway, acts through the Tool Runner, and
    observes into the world model. Drive it toward a goal with the
    :class:`~attack_engine.orchestrator.controller.ObjectiveController`.
    """

    if ctx.gateway is None:
        raise ValueError("recon loop requires a model gateway in the AgentContext")
    planner = LlmPlanner(
        ctx.gateway,
        tools=list(tools or DEFAULT_RECON_TOOLS),
        system_prompt=RECON_SYSTEM_PROMPT,
        tier=tier,
        actor_name="recon",
        engagement_id=ctx.engagement_id,
    )
    return ReasoningLoop(
        planner,
        ToolRunnerActor(ctx.tool_runner),
        ReconObserver(),
        max_steps=max_steps,
        seed_actions=_recon_seed_actions,
    )
