"""Surface Mapper — the recon tool-driver archetype (spec §4, step 2).

Read-only asset & service discovery. It drives Nmap for network recon and ffuf
for web-surface discovery, then writes assets/services to the blackboard and
*proposes* findings for each observation. It confirms nothing — that is the
Verifier's job in Sprint 1 (propose/verify, rule #1). Being read-only, it needs
no gate.

This one archetype is what the spec means by "instantiated twice via different
tool bindings": the same class becomes a network mapper or a web mapper purely
by which tools its spec lists — no subclass per tool (rule #3).
"""

from __future__ import annotations

from typing import Any

from ...gateway.types import ChatMessage
from ...logging import get_logger
from ...schemas.findings import Asset, Finding, Priority, Service
from ...schemas.tools import ToolProfile
from ..base import Agent

_log = get_logger("agent.surface_mapper")

#: Ports we follow up on with web content discovery.
_WEB_PORTS: dict[int, str] = {80: "http", 8080: "http", 8000: "http", 3000: "http",
                              443: "https", 8443: "https"}


class SurfaceMapper(Agent):
    """Discovers live hosts, services, versions, and web surface (read-only)."""

    def _execute(self, targets: list[str]) -> None:
        for target in targets:
            self._map_target(target)
        # Optional BYOM narrative summary of the inventory (audited, tier-routed).
        self._summarize()

    def _map_target(self, target: str) -> None:
        # 1. Optional fast masscan sweep to narrow the ports Nmap must detail.
        ports_arg = self._masscan_sweep(target)

        # 2. Nmap for accurate service/version detection (on the swept ports if
        #    masscan found any, otherwise its default set).
        profile = ToolProfile(
            preset="default", args={"ports": ports_arg} if ports_arg else {}
        )
        nmap_result = self.run_tool("nmap", target, profile)
        if nmap_result is None:  # out-of-scope + skip policy
            return
        open_ports = nmap_result.parsed.get("ports", [])
        asset = self._ingest_asset(target, open_ports, nmap_result.audit_id)

        # 3. Enrich web services with httpx tech/version fingerprinting.
        if "httpx" in self.spec.tools:
            self._enrich_http(target, open_ports)

        # 4. Follow up on any web ports with content discovery, if ffuf is bound.
        if "ffuf" in self.spec.tools:
            for svc in open_ports:
                scheme = _WEB_PORTS.get(int(svc["port"]))
                if scheme is not None:
                    self._map_web(target, int(svc["port"]), scheme, asset)

    def _masscan_sweep(self, target: str) -> str | None:
        """Fast pre-sweep; returns a comma-separated port list or None."""

        if "masscan" not in self.spec.tools:
            return None
        result = self.run_tool(
            "masscan", target, ToolProfile(args={"ports": "1-1024", "rate": "1000"})
        )
        if result is None or not result.parsed.get("ports"):
            return None
        return ",".join(str(p["port"]) for p in result.parsed["ports"])

    def _enrich_http(self, target: str, open_ports: list[dict[str, Any]]) -> None:
        for svc in open_ports:
            scheme = _WEB_PORTS.get(int(svc["port"]))
            if scheme is None:
                continue
            result = self.run_tool(
                "httpx", target,
                ToolProfile(args={"scheme": scheme, "port": int(svc["port"])}),
            )
            if result is None:
                continue
            for hit in result.parsed.get("results", []):
                server = hit.get("webserver")
                if not server:
                    continue
                self.ctx.store.propose_finding(
                    Finding(
                        engagement_id=self.ctx.engagement_id,
                        asset=target,
                        service=server,
                        type=f"web-tech:{svc['port']}",
                        title=f"{server} ({', '.join(hit.get('tech', []))})".strip(),
                        priority=Priority.INFORMATIONAL,
                        evidence=(f"raw:{result.audit_id}",),
                        proposed_by=self.spec.id,
                        metadata={"port": int(svc["port"]), "status": hit.get("status")},
                    ),
                    emitted_by=self.spec.id,
                )
                self._note_finding()

    def _ingest_asset(
        self, target: str, open_ports: list[dict[str, Any]], audit_id: str
    ) -> Asset:
        services = tuple(
            Service(
                port=int(p["port"]),
                protocol=p.get("protocol", "tcp"),
                name=p.get("service"),
                product=p.get("product"),
                version=p.get("version"),
            )
            for p in open_ports
        )
        asset = Asset(
            address=target,
            services=services,
            engagement_id=self.ctx.engagement_id,
        )
        stored = self.ctx.store.add_asset(asset, emitted_by=self.spec.id)
        self._note_asset()

        # Propose one observation finding per exposed service (rule #1: propose).
        for svc in services:
            finding = Finding(
                engagement_id=self.ctx.engagement_id,
                asset=target,
                service=svc.cpe_hint,
                type=f"exposed-service:{svc.port}/{svc.protocol}",
                title=f"Exposed {svc.name or 'service'} on {target}:{svc.port}",
                priority=Priority.INFORMATIONAL,
                evidence=(f"raw:{audit_id}",),
                proposed_by=self.spec.id,
            )
            self.ctx.store.propose_finding(finding, emitted_by=self.spec.id)
            self._note_finding()
        return stored

    def _map_web(self, target: str, port: int, scheme: str, asset: Asset) -> None:
        profile = ToolProfile(
            args={"scheme": scheme, "port": port, "match_codes": "200,204,301,302,401,403"}
        )
        ffuf_result = self.run_tool("ffuf", target, profile)
        if ffuf_result is None:
            return
        for hit in ffuf_result.parsed.get("results", []):
            path = hit.get("path")
            if not path:
                continue
            finding = Finding(
                engagement_id=self.ctx.engagement_id,
                asset=target,
                service=f"{scheme}/{port}",
                type=f"web-path:{path}",
                title=f"Discovered path /{path} ({hit.get('status')}) on {target}:{port}",
                priority=Priority.INFORMATIONAL,
                evidence=(f"raw:{ffuf_result.audit_id}",),
                proposed_by=self.spec.id,
            )
            self.ctx.store.propose_finding(finding, emitted_by=self.spec.id)
            self._note_finding()

    def _summarize(self) -> None:
        """Ask the model for a short inventory narrative (BYOM, optional)."""

        if self.ctx.gateway is None:
            return
        assets = self.ctx.store.assets()
        lines = [
            f"{a.address}: " + ", ".join(f"{s.port}/{s.protocol}" for s in a.services)
            for a in assets
        ]
        prompt = (
            "You are a recon summariser. In one sentence, summarise this asset "
            "inventory. Do NOT infer vulnerabilities.\n" + "\n".join(lines)
        )
        try:
            resp = self.ctx.gateway.complete(
                [ChatMessage.system("Be concise and factual."), ChatMessage.user(prompt)],
                tier=self.spec.model_tier,
                engagement_id=self.ctx.engagement_id,
                actor=self.spec.id,
            )
            _log.info("recon summary", agent=self.spec.id, summary=resp.text[:200])
        except Exception:
            _log.warning("summary generation failed", agent=self.spec.id)
