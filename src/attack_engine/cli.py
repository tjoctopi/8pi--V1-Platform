"""Command-line interface for the 8π Coordinated Attack Engine.

Sprint 0 surface: run a scoped recon engagement, inspect the resulting asset
inventory + proposed findings, verify the audit chain, and manage the
ground-truth range. Every offensive capability stays behind the same scope and
audit machinery the library enforces — the CLI is a thin driver, not a bypass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import get_settings
from .engine import Engagement, Engine, load_scope
from .netutil import web_targets
from .orchestrator.report import EngagementReport

app = typer.Typer(
    add_completion=False,
    help="8π Coordinated Attack Engine — purple-team automation (BYOM).",
    no_args_is_help=True,
)
range_app = typer.Typer(help="Manage the ground-truth cyber range.")
audit_app = typer.Typer(help="Inspect and verify the immutable audit log.")
app.add_typer(range_app, name="range")
app.add_typer(audit_app, name="audit")

console = Console()
_RANGE_DIR = Path(__file__).resolve().parent.parent.parent / "range"
_SPECS_DIR = Path(__file__).resolve().parent / "agents/specs"
_DEFAULT_SPEC = _SPECS_DIR / "surface_mapper.yaml"


@app.command()
def version() -> None:
    """Print the engine version."""

    console.print(f"[bold cyan]8π Coordinated Attack Engine[/] v{__version__}")


@app.command()
def recon(
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Signed engagement scope YAML."),
    targets: list[str] = typer.Argument(..., help="Targets (IP/host) to map."),
    spec_file: Path = typer.Option(_DEFAULT_SPEC, "--spec", help="Agent spec YAML."),
    require_signed: bool = typer.Option(False, help="Refuse an unsigned scope."),
) -> None:
    """Run a scoped, read-only recon engagement (Surface Mapper)."""

    from .agents.loader import load_spec

    engine = Engine.from_settings()
    scope = load_scope(scope_file)
    engagement = engine.engagement(scope, require_signed=require_signed)
    spec = load_spec(spec_file)

    console.print(
        f"[bold]Engagement[/] {scope.engagement_id} · "
        f"provider={engine.gateway.provider_name} · sandbox={engine.sandbox.name}"
    )
    report = engagement.run_agent(spec, list(targets))

    _render_assets(engagement)
    _render_findings(engagement)

    console.print(
        f"\n[bold]Run:[/] stopped={report.stopped_reason} "
        f"tool_calls={report.tool_calls} assets={report.assets_found} "
        f"findings={report.findings_proposed} "
        f"skipped={len(report.skipped_targets)} "
        f"duration={report.duration_sec}s"
    )
    ok = engine.audit.verify()
    head = engine.audit.head()
    console.print(
        f"[bold]Audit:[/] entries={len(engine.audit)} "
        f"chain_intact={'[green]yes[/]' if ok else '[red]NO[/]'} "
        f"head={head.entry_hash[:12] if head else '-'}…"
    )


@app.command()
def intel(
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Signed engagement scope YAML."),
    targets: list[str] = typer.Argument(..., help="Targets (IP/host) to profile."),
    require_signed: bool = typer.Option(False, help="Refuse an unsigned scope."),
    active: bool = typer.Option(
        False, "--active/--passive",
        help="Actively screen injection points (slower, touches the target more).",
    ),
    markdown: bool = typer.Option(True, "--markdown/--no-markdown", help="Print the dossier."),
) -> None:
    """Gather an attack-surface intelligence dossier on any target (capture-first).

    Recon → CVE correlation → web capture (endpoints, params, tech, exposed items,
    nuclei observations), assembled into an offensive dossier: services+versions,
    attack leads, exposed items and observations per asset. Read-only; by default
    it enumerates injection points as leads without probing them (``--passive``).
    """

    from .agents.loader import load_spec
    from .intel.surface import build_attack_surface

    engine = Engine.from_settings()
    scope = load_scope(scope_file)
    engagement = engine.engagement(scope, require_signed=require_signed)

    console.print(
        f"[bold]Intel[/] {scope.engagement_id} · provider={engine.gateway.provider_name} "
        f"· sandbox={engine.sandbox.name} · mode={'active' if active else 'passive'}"
    )

    # 1. Recon → assets/services/paths. 2. Verify+correlate → CVE leads from versions.
    engagement.run_agent(load_spec(_DEFAULT_SPEC), list(targets))
    engagement.verify()
    engagement.correlate()

    # 3. Web capture over every reachable web service (screen gated by --active).
    web_spec = load_spec(_SPECS_DIR / "web_inquisitor.yaml")
    web_spec = web_spec.model_copy(update={
        "guardrails": web_spec.guardrails.model_copy(
            update={"active_injection_screen": active}
        )
    })
    targets_web = web_targets(engagement.store)
    if targets_web:
        engagement.run_agent(web_spec, targets_web)
        if active:
            # Confirm the injection/XSS/redirect leads read-only, then finalise
            # verified vulns into CONFIRMED (reachability-scored) leads.
            engagement.verify()
            engagement.correlate()

    surface = build_attack_surface(engagement.store)
    if markdown:
        console.print(surface.to_markdown())
    console.print(
        f"\n[bold]Dossier:[/] assets={len(surface.assets)} "
        f"leads={surface.total_leads} ([red]{surface.confirmed_leads} confirmed[/]) "
        f"· audit entries={len(engine.audit)} "
        f"chain_intact={'[green]yes[/]' if engine.audit.verify() else '[red]NO[/]'}"
    )


def _render_assets(engagement: Engagement) -> None:
    table = Table(title="Asset Inventory", show_lines=False)
    table.add_column("Address", style="cyan")
    table.add_column("Reachable")
    table.add_column("Services")
    for asset in engagement.store.assets():
        svcs = ", ".join(
            f"{s.port}/{s.protocol}"
            + (f" {s.product}" if s.product else "")
            + (f" {s.version}" if s.version else "")
            for s in asset.services
        )
        reachable = engagement.store.graph.is_reachable(asset.id)
        table.add_row(asset.address, "✓" if reachable else "✗", svcs or "—")
    console.print(table)


def _render_findings(engagement: Engagement) -> None:
    findings = engagement.store.findings()
    if not findings:
        return
    table = Table(title="Findings (proposed)", show_lines=False)
    table.add_column("Type", style="magenta")
    table.add_column("Asset")
    table.add_column("State")
    table.add_column("Reachable")
    for f in findings:
        table.add_row(f.type, f.asset, f.state.value, "✓" if f.reachable else "✗")
    console.print(table)


_PRIORITY_ORDER = {
    "patch_immediately": 0, "high": 1, "medium": 2, "low": 3, "informational": 4,
}


@app.command()
def assess(
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Signed engagement scope YAML."),
    targets: list[str] = typer.Argument(..., help="Targets (IP/host) to assess."),
    require_signed: bool = typer.Option(False, help="Refuse an unsigned scope."),
) -> None:
    """Run the autonomous pipeline: recon → verify → correlate (read-only, no gates)."""

    from .agents.loader import load_spec

    engine = Engine.from_settings()
    scope = load_scope(scope_file)
    engagement = engine.engagement(scope, require_signed=require_signed)
    spec = load_spec(_DEFAULT_SPEC)

    console.print(
        f"[bold]Engagement[/] {scope.engagement_id} · "
        f"provider={engine.gateway.provider_name} · sandbox={engine.sandbox.name}"
    )
    engagement.run_agent(spec, list(targets))
    vreport = engagement.verify()
    creport = engagement.correlate()

    _render_assets(engagement)
    _render_prioritized(engagement)

    console.print(
        f"\n[bold]Verify:[/] verified={vreport.verified} rejected={vreport.rejected} "
        f"skipped={vreport.skipped}"
    )
    console.print(
        f"[bold]Correlate:[/] services={creport.services_scanned} "
        f"cves_confirmed={creport.cves_confirmed} "
        f"[red]patch_now={creport.patch_immediately}[/] "
        f"deprioritized={creport.deprioritized}"
    )
    ok = engine.audit.verify()
    console.print(
        f"[bold]Audit:[/] entries={len(engine.audit)} "
        f"chain_intact={'[green]yes[/]' if ok else '[red]NO[/]'}"
    )


def _render_prioritized(engagement: Engagement) -> None:
    from .schemas.findings import FindingState

    confirmed = engagement.store.findings(FindingState.CONFIRMED)
    if not confirmed:
        return
    confirmed.sort(key=lambda f: (_PRIORITY_ORDER.get(f.priority.value if f.priority else "", 9),
                                  -(f.exploit_prob or 0)))
    table = Table(title="Confirmed vulnerabilities (reachability-prioritised)")
    table.add_column("Priority", style="bold")
    table.add_column("Type", style="magenta")
    table.add_column("Asset")
    table.add_column("KEV")
    table.add_column("Exploit prob")
    for f in confirmed:
        pr = f.priority.value if f.priority else "—"
        colour = "red" if pr == "patch_immediately" else ("yellow" if pr == "high" else "white")
        table.add_row(
            f"[{colour}]{pr}[/]", f.type, f.asset,
            "✓" if f.on_kev else "—",
            f"{f.exploit_prob:.2f}" if f.exploit_prob is not None else "—",
        )
    console.print(table)


@app.command()
def engage(
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Signed engagement scope YAML."),
    targets: list[str] = typer.Argument(..., help="Targets (IP/host) for the engagement."),
    goal: str = typer.Option("assess", help="Engagement goal."),
    objective: str = typer.Option(
        "", "--objective",
        help="Kill-chain objective as HOST[:PRIVILEGE], e.g. 10.5.0.99:root.",
    ),
    require_signed: bool = typer.Option(False, help="Refuse an unsigned scope."),
    markdown: bool = typer.Option(False, "--markdown", help="Print the full Markdown report."),
) -> None:
    """Run the full coordinated purple-team loop (Orchestrator + Blue Sentry).

    plan → recon → verify → web → confirm (gated) → correlate → convert → report.
    With --objective, also plans the goal-directed kill chain to that target
    (planning only; impact phases are human-gated and operator-driven).
    Applying fixes + re-test is a separate gated step and is not run here.
    """

    engine = Engine.from_settings()
    scope = load_scope(scope_file)
    engagement = engine.engagement(scope, require_signed=require_signed)
    blue = engine.blue_sentry(scope)
    orch = engagement.orchestrator(blue_sentry=blue)

    obj: tuple[str, str] | None = None
    if objective:
        host, _, priv = objective.partition(":")
        obj = (host, priv or "root")

    console.print(
        f"[bold]Engagement[/] {scope.engagement_id} · goal={goal} · "
        f"provider={engine.gateway.provider_name} · sandbox={engine.sandbox.name}"
    )
    result = orch.run(list(targets), goal=goal, objective=obj)
    report = result.report

    verdict = report.breach
    banner = "red" if verdict.breachable else "green"
    console.print(
        f"\n[bold {banner}]{'⚠ ' if verdict.breachable else '✓ '}"
        f"{verdict.summary()}[/]"
    )
    for fh in verdict.footholds:
        route = " → ".join(fh.entry_path) if fh.entry_path else fh.asset
        console.print(
            f"   [red]•[/] {fh.finding_type} on {fh.asset} "
            f"([magenta]{fh.technique}[/], prob "
            f"{fh.exploit_prob:.2f})  route: {route}" if fh.exploit_prob is not None
            else f"   [red]•[/] {fh.finding_type} on {fh.asset} "
            f"([magenta]{fh.technique}[/])  route: {route}"
        )

    _render_prioritized_from_report(report)
    if markdown:
        console.print("\n" + report.to_markdown())

    if report.kill_chain is not None:
        console.print("\n[bold]Kill chain to objective[/]")
        console.print(report.kill_chain.to_markdown())

    console.print(f"\n[bold]Phases:[/] {' → '.join(result.plan.phase_names())}")
    console.print(
        f"[bold]Result:[/] confirmed={len(report.confirmed)} "
        f"remediations={len(report.remediations)} "
        f"[red]blue_alerts={report.blue_alerts}[/]"
    )
    console.print(
        f"[bold]Audit:[/] entries={report.audit_entries} "
        f"chain_intact={'[green]yes[/]' if report.audit_intact else '[red]NO[/]'}"
    )


def _render_prioritized_from_report(report: EngagementReport) -> None:
    if not report.confirmed:
        console.print("[dim]No confirmed vulnerabilities.[/]")
        return
    table = Table(title="Confirmed vulnerabilities (reachability-prioritised)")
    table.add_column("Priority", style="bold")
    table.add_column("Type", style="magenta")
    table.add_column("Asset")
    table.add_column("KEV")
    table.add_column("Exploit prob")
    for f in report.confirmed:
        pr = f.priority.value if f.priority else "—"
        colour = "red" if pr == "patch_immediately" else ("yellow" if pr == "high" else "white")
        table.add_row(
            f"[{colour}]{pr}[/]", f.type, f.asset,
            "✓" if f.on_kev else "—",
            f"{f.exploit_prob:.2f}" if f.exploit_prob is not None else "—",
        )
    console.print(table)


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify the configured audit log's hash chain."""

    from .governance.audit import AuditLog
    from .governance.audit_backends import build_audit_backend

    settings = get_settings()
    audit = AuditLog(build_audit_backend(settings))
    try:
        audit.verify()
    except Exception as exc:
        console.print(f"[red]AUDIT INTEGRITY FAILURE:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(
        f"[green]Audit chain intact[/] — {len(audit)} entries "
        f"({settings.audit_backend.value})"
    )


@range_app.command("up")
def range_up() -> None:
    """Start the ground-truth range (docker compose up -d)."""

    _compose(["up", "-d"])


@range_app.command("down")
def range_down() -> None:
    """Stop and remove the ground-truth range."""

    _compose(["down", "-v"])


@range_app.command("status")
def range_status() -> None:
    """Show range container status."""

    _compose(["ps"])


def _compose(args: list[str]) -> None:
    compose_file = _RANGE_DIR / "docker-compose.yml"
    if not compose_file.exists():
        console.print(f"[red]range compose file not found:[/] {compose_file}")
        raise typer.Exit(code=1)
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    console.print(f"[dim]$ {' '.join(cmd)}[/]")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError as exc:
        console.print("[red]docker not found on PATH[/]")
        raise typer.Exit(code=1) from exc
    except subprocess.CalledProcessError as exc:
        raise typer.Exit(code=exc.returncode) from exc


if __name__ == "__main__":
    app()
