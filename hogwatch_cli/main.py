from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path for direct script execution
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.detector import run_detection
from core.models import Finding, Severity, TimelineEntry
from core.parser import load_scenario
from core.report import generate_report, save_report
from core.timeline import build_timeline

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}

_PHASE_MAP: dict[str, str] = {
    # AWS phases
    "AWS-004": "Reconnaissance",
    "AWS-002": "Credential Theft",
    "AWS-001": "Credential Abuse",
    "AWS-003": "Data Exfiltration",
    "AWS-CHAIN": "Full Attack Chain Confirmed",
    # PostHog phases
    "PH-001": "Initial Access",
    "PH-002": "Initial Access",
    "PH-003": "Discovery",
    "PH-004": "Privilege Escalation",
    "PH-005": "Data Access",
    "PH-006": "Exfiltration",
    "PH-CHAIN": "Full Attack Chain Confirmed",
    # Temporal
    "TW-001": "Exfiltration",
    "TW-002": "Persistence",
    "TW-003": "Defense Evasion",
    "TW-CHAIN": "Full Attack Chain Confirmed",
    # Celery
    "CT-001": "Initial Access",
    "CT-002": "Persistence",
    "CT-003": "Execution",
    "CT-004": "Full Attack Chain Confirmed",
    # OTel
    "OT-001": "Data Exfiltration",
    "OT-002": "Data Access",
    "OT-003": "Lateral Movement",
    "OT-004": "Full Attack Chain Confirmed",
    # Exception/Middleware
    "EM-001": "Discovery",
    "EM-002": "Initial Access",
    "EM-003": "Discovery",
    "EM-004": "Full Attack Chain Confirmed",
    # Plugin
    "PS-001": "Initial Access",
    "PS-002": "Exfiltration",
    "PS-003": "Credential Access",
    "PS-004": "Full Attack Chain Confirmed",
    # Prometheus
    "PM-001": "Credential Access",
    "PM-002": "Exfiltration",
    "PM-003": "Impact",
    # MCP
    "MCP-001": "Initial Access",
    "MCP-002": "Collection",
    "MCP-003": "Exfiltration",
    "MCP-004": "Full Attack Chain Confirmed",
    # HogQL
    "HQL-001": "Reconnaissance",
    "HQL-002": "Data Exfiltration",
    "HQL-003": "Data Exfiltration",
    "HQL-CHAIN": "Full Attack Chain Confirmed",
}


@click.group()
def cli():
    """hogwatch-ai — Simulate and investigate security incidents with LLMs."""
    pass


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--no-llm", is_flag=True, help="Skip LLM investigation")
@click.option("--model", default=None, help="Claude model to use")
@click.option("--output", default="output", help="Output directory for reports")
@click.option("--verbose", is_flag=True, help="Show detailed output")
def investigate(scenario: str, no_llm: bool, model: str | None, output: str, verbose: bool):
    """Run full investigation pipeline on a scenario file."""
    console.print(Panel("[bold]hogwatch-ai[/bold] — Investigation Mode", style="blue"))

    # Parse
    with console.status("[bold green]Parsing scenario..."):
        metadata, events = load_scenario(scenario)
    console.print(f"  Loaded [bold]{len(events)}[/bold] events from [cyan]{metadata['title']}[/cyan]")

    # Detect
    with console.status("[bold green]Running detection rules..."):
        findings = run_detection(events)
    _print_findings_summary(findings)

    # Timeline
    with console.status("[bold green]Building timeline..."):
        timeline = build_timeline(events, findings)

    if verbose:
        _print_timeline_table(timeline)

    # Attack metrics
    _print_attack_metrics(events, findings)

    # LLM Investigation
    investigation = None
    if not no_llm:
        try:
            from llm.client import investigate as llm_investigate

            with console.status("[bold green]Claude is investigating..."):
                investigation = llm_investigate(timeline, findings, metadata, model)
            console.print("\n[bold green]AI Investigation Complete[/bold green]")
            if investigation.summary:
                console.print(Panel(investigation.summary, title="Summary", style="green"))
            if investigation.is_malicious:
                console.print(
                    f"  Assessment: [bold red]MALICIOUS[/bold red] "
                    f"(confidence: {investigation.confidence})"
                )
        except Exception as e:
            console.print(f"[yellow]LLM investigation failed: {e}[/yellow]")
            console.print("[yellow]Continuing without AI analysis...[/yellow]")

    # Report
    report_content = generate_report(metadata, timeline, findings, investigation)
    report_path = save_report(report_content, output)
    console.print(f"\n  Report saved to [bold cyan]{report_path}[/bold cyan]")


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--delay", default=2.0, type=float, help="Delay between events (seconds)")
@click.option("--no-llm", is_flag=True, help="Skip LLM investigation at end")
@click.option("--model", default=None, help="Claude model to use")
@click.option("--output", default="output", help="Output directory for reports")
def simulate(scenario: str, delay: float, no_llm: bool, model: str | None, output: str):
    """Simulate a real-time attack replay with incremental detection."""
    console.print(Panel("[bold]hogwatch-ai[/bold] — Simulation Mode", style="red"))

    metadata, events = load_scenario(scenario)
    console.print(
        f"  Replaying [bold]{len(events)}[/bold] events from "
        f"[cyan]{metadata['title']}[/cyan]\n"
    )

    all_findings: list[Finding] = []
    seen_rule_ids: set[str] = set()
    current_phase: str | None = None
    # Build the event list incrementally by appending instead of slicing
    # to avoid allocating a new list copy on every iteration.
    # Note: detection still runs on the full accumulated list each iteration
    # so that correlation rules can inspect all prior events. For a demo tool
    # with <200 events this is acceptable; a production system would use
    # stateful / incremental detection.
    events_so_far: list = []

    for i, event in enumerate(events):
        events_so_far.append(event)

        # Print event
        ts = event.timestamp.strftime("%H:%M:%S")
        source_style = "cyan" if event.event_type == "cloudtrail" else "magenta"
        console.print(
            f"  [{source_style}]{ts}[/{source_style}] "
            f"[bold]{event.event_name}[/bold] "
            f"by {event.actor or 'service'} "
            f"({event.source})"
        )

        # Incremental detection
        current_findings = run_detection(events_so_far)
        new_findings = [f for f in current_findings if f.rule_id not in seen_rule_ids]

        for f in new_findings:
            seen_rule_ids.add(f.rule_id)
            all_findings.append(f)

            # Phase transition banner
            phase = _PHASE_MAP.get(f.rule_id)
            if phase and phase != current_phase:
                current_phase = phase
                console.print(f"\n  [bold white on red] ━━━ Phase: {phase} ━━━ [/bold white on red]\n")

            style = SEVERITY_COLORS.get(f.severity, "")
            console.print(
                f"    [{style}]>> ALERT: [{f.severity.value.upper()}] "
                f"{f.rule_id} — {f.title}[/{style}]"
            )

        if i < len(events) - 1:
            time.sleep(delay)

    # Final summary
    console.print(f"\n  Simulation complete: {len(events)} events, {len(all_findings)} findings")
    _print_findings_summary(all_findings)

    # Attack metrics
    _print_attack_metrics(events, all_findings)

    # Full investigation at the end
    timeline = build_timeline(events, all_findings)

    investigation = None
    if not no_llm:
        try:
            from llm.client import investigate as llm_investigate

            with console.status("[bold green]Claude is investigating..."):
                investigation = llm_investigate(timeline, all_findings, metadata, model)
            console.print("\n[bold green]AI Investigation Complete[/bold green]")
            if investigation.summary:
                console.print(Panel(investigation.summary, title="Summary", style="green"))
        except Exception as e:
            console.print(f"[yellow]LLM investigation failed: {e}[/yellow]")

    report_content = generate_report(metadata, timeline, all_findings, investigation)
    report_path = save_report(report_content, output)
    console.print(f"\n  Report saved to [bold cyan]{report_path}[/bold cyan]")


@cli.command("list-scenarios")
@click.option("--data-dir", default="data", help="Directory containing scenario files")
def list_scenarios(data_dir: str):
    """List available scenarios."""
    data_path = Path(data_dir)
    if not data_path.exists():
        console.print(f"[red]Directory not found: {data_dir}[/red]")
        return

    table = Table(title="Available Scenarios")
    table.add_column("File", style="cyan")
    table.add_column("Title", style="bold")
    table.add_column("Source Type")
    table.add_column("MITRE Techniques", style="yellow")
    table.add_column("Events", justify="right")

    for f in sorted(data_path.glob("scenario_*.json")):
        with open(f) as fh:
            data = json.load(fh)
        meta = data.get("metadata", {})
        table.add_row(
            f.name,
            meta.get("title", "?"),
            meta.get("source_type", "?"),
            ", ".join(meta.get("mitre_techniques", [])),
            str(len(data.get("events", []))),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_attack_metrics(
    events: list,
    findings: list[Finding],
) -> None:
    """Print a compact attack summary panel with key metrics."""
    if not events:
        return

    # --- Duration ---
    timestamps = [e.timestamp for e in events]
    first_ts = min(timestamps)
    last_ts = max(timestamps)
    delta = last_ts - first_ts
    total_seconds = int(delta.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        duration_str = f"{hours}h {minutes:02d}m"
    else:
        duration_str = f"{minutes}m {seconds:02d}s"

    # --- Findings by severity ---
    severity_counts: dict[Severity, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    severity_parts = [
        f"{severity_counts[s]} {s.value}"
        for s in severity_order
        if s in severity_counts
    ]
    findings_str = ", ".join(severity_parts) if severity_parts else "none"

    # --- MITRE techniques ---
    techniques: set[str] = set()
    for f in findings:
        if f.mitre_technique:
            techniques.add(f.mitre_technique)
    techniques_str = ", ".join(sorted(techniques)) if techniques else "none"

    # --- Attack chains ---
    chains = [f for f in findings if f.rule_id.endswith("-CHAIN")]
    if chains:
        chain_ids = ", ".join(f.rule_id for f in chains)
        chains_str = f"{len(chains)} ({chain_ids})"
    else:
        chains_str = "0"

    # Build table
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Duration", duration_str)
    table.add_row("Events analyzed", str(len(events)))
    table.add_row("Findings", findings_str)
    table.add_row("MITRE techniques", techniques_str)
    table.add_row("Attack chains", chains_str)

    console.print(Panel(table, title="Attack Summary", style="bold"))


def _print_findings_summary(findings: list[Finding]):
    """Print a compact findings summary."""
    if not findings:
        console.print("  [green]No findings detected.[/green]")
        return

    console.print(f"\n  [bold]{len(findings)} findings detected:[/bold]")
    for f in findings:
        style = SEVERITY_COLORS.get(f.severity, "")
        console.print(f"    [{style}][{f.severity.value.upper():8s}] {f.rule_id}: {f.title}[/{style}]")


def _print_timeline_table(timeline: list[TimelineEntry]):
    """Print a rich timeline table."""
    table = Table(title="Event Timeline")
    table.add_column("Time", style="dim")
    table.add_column("Relative")
    table.add_column("Event")
    table.add_column("Findings", style="yellow")

    for entry in timeline:
        ts = entry.timestamp.strftime("%H:%M:%S")
        finding_tags = ", ".join(f.rule_id for f in entry.findings) if entry.findings else ""
        style = "bold red" if entry.is_suspicious else ""
        table.add_row(ts, entry.relative_time, entry.description[:60], finding_tags, style=style)

    console.print(table)


if __name__ == "__main__":
    cli()
