"""Command-line interface.

    shyena scan [PATH] [--depth quick|standard|deep|audit] [--base origin/main]
    shyena tools
    shyena list
    shyena show <id>
    shyena policy [PATH]
    shyena mark <fingerprint> --status accepted|false_positive|open --reason "..."
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from shyena import __version__, engine, report, store
from shyena import depth as depth_mod
from shyena import policy as policy_mod
from shyena import repo as repo_mod
from shyena.fingerprint import short
from shyena.models import FindingStatus, Severity
from shyena.probes import all_probes

app = typer.Typer(
    help="Shyena — profile a repository for vulnerabilities, dependencies, licences, secrets, smell and compatibility.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_STATUS_STYLE = {
    FindingStatus.NEW: "bold red",
    FindingStatus.RECURRING: "yellow",
    FindingStatus.FIXED: "green",
    FindingStatus.ACCEPTED: "dim",
    FindingStatus.FALSE_POSITIVE: "dim",
}


def _version(value: bool) -> None:
    if value:
        console.print(f"shyena {__version__}")
        raise typer.Exit()


@app.callback()
def _root(version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version and exit.")) -> None:
    """Shyena, the sharp-eyed hawk."""


# ------------------------------------------------------------------------------ scan


@app.command()
def scan(
    path: str = typer.Argument(".", help="Repository root."),
    depth: Optional[str] = typer.Option(None, "--depth", "-d", help="quick | standard | deep | audit, or a profile from the policy."),
    base: Optional[str] = typer.Option(None, "--base", "-b", help="Base ref the change is measured against (e.g. origin/main)."),
    policy: Optional[Path] = typer.Option(None, "--policy", "-p", help="Policy file (default: .shyena.yml at the root)."),
    baseline: Optional[str] = typer.Option(None, "--baseline", help="Scan id to diff against (default: auto)."),
    trigger: str = typer.Option("pull_request", "--trigger", "-t", help="pull_request | default_branch | release_tag | manual"),
    name: Optional[str] = typer.Option(None, "--name", help="Name for the scan (default: directory name)."),
    fail: bool = typer.Option(True, "--fail/--no-fail", help="Exit 1 when the gate fails."),
    as_json: bool = typer.Option(False, "--json", help="Print the JSON summary only."),
) -> None:
    """Scan a repository and evaluate the policy gate."""
    if trigger not in depth_mod.TRIGGERS:
        raise typer.BadParameter(f"Unknown trigger {trigger!r}. Choose from: {', '.join(depth_mod.TRIGGERS)}")

    def on_event(event: str, payload: dict) -> None:
        if as_json:
            return
        if event == "run_start":
            extra = " (first scan: whole tree)" if payload.get("onboarding") else ""
            console.print(f"[bold]Shyena[/bold] scan [dim]{payload['scan_id']}[/dim] | depth [cyan]{payload['depth']}[/cyan]{extra}")
            console.print(f"  probes: {', '.join(payload['probes']) or 'none installed'}")
        elif event == "probe_start":
            console.print(f"  [dim]>[/dim] {payload['probe']} ...", end="")
        elif event == "probe_done":
            status = payload["status"]
            colour = {"completed": "green", "skipped": "yellow", "error": "red"}.get(status, "white")
            detail = payload.get("error") or payload.get("note") or f"{payload['findings']} findings"
            console.print(f" [{colour}]{status}[/{colour}] [dim]{detail}[/dim]")
        elif event == "probe_skipped":
            console.print(f"  [dim]-[/dim] {payload['probe']} [yellow]skipped[/yellow] [dim]{payload['note']}[/dim]")

    try:
        run = engine.scan(
            path,
            depth=depth,
            base=base,
            policy_path=policy,
            baseline_id=baseline,
            trigger=trigger,
            name=name,
            on_event=on_event,
        )
    except (FileNotFoundError, ValueError) as exc:
        if isinstance(exc, UnicodeError):  # a console problem, not a bad argument
            raise
        raise typer.BadParameter(str(exc)) from exc

    if as_json:
        console.print_json(json.dumps(report.summary(run)))
    else:
        _print_summary(run)
    if fail and run.gate is not None and not run.gate.passed:
        raise typer.Exit(code=1)


def _print_summary(run) -> None:
    gate = run.gate
    verdict = "[bold green]PASS[/bold green]" if gate and gate.passed else "[bold red]FAIL[/bold red]"
    console.print()
    console.print(f"Gate {verdict}  |  scan [dim]{run.id}[/dim]  |  {run.status}")
    if gate:
        for reason in gate.reasons:
            console.print(f"  [red]x[/red] {reason}")
        for warning in gate.warnings:
            console.print(f"  [yellow]![/yellow] {warning}")
    new = run.by_status(FindingStatus.NEW)
    console.print(
        f"  findings: [bold]{len(new)} new[/bold], {len(run.by_status(FindingStatus.RECURRING))} recurring, "
        f"{len(run.fixed)} fixed, {len(run.by_status(FindingStatus.ACCEPTED)) + len(run.by_status(FindingStatus.FALSE_POSITIVE))} dismissed"
    )
    if new:
        _findings_table(new[:25], title="New findings" + (" (first 25)" if len(new) > 25 else ""))
    console.print(f"  report: {store.scan_dir(run.id) / 'report.md'}")


def _findings_table(findings, title: str) -> None:
    table = Table(title=title, show_lines=False)
    table.add_column("Sev")
    table.add_column("Status")
    table.add_column("Dimension")
    table.add_column("Fingerprint", style="dim")
    table.add_column("Finding")
    table.add_column("Where")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        loc = f.primary
        where = f"{loc.path}:{loc.start_line}" if loc and loc.start_line else (loc.path if loc else f.component or "")
        table.add_row(
            f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f"[{_STATUS_STYLE[f.status]}]{f.status.value}[/]",
            f.category.value,
            short(f.id),
            f.title[:90],
            where,
        )
    console.print(table)


# ----------------------------------------------------------------------------- tools


@app.command()
def tools() -> None:
    """List engines and whether each is installed."""
    table = Table(title="Shyena engines")
    table.add_column("Probe", style="bold")
    table.add_column("Dimension")
    table.add_column("Pass")
    table.add_column("Output")
    table.add_column("Status")
    table.add_column("Notes")
    for probe in all_probes():
        available = probe.is_available()
        status = "[green]installed[/green]" if available else "[red]missing[/red]"
        table.add_row(probe.name, probe.category.value, probe.scan_pass.value, probe.native_output, status, "" if available else probe.install_hint)
    table.add_row("licence-policy", "licence", "fast", "findings", "[green]built in[/green]", "our policy engine over the SBOM")
    table.add_row("triage:null", "all", "fast", "verdicts", "[green]built in[/green]", "Claude / Ollama providers land in Phase 1")
    console.print(table)


# ------------------------------------------------------------------------------ list


@app.command("list")
def list_cmd() -> None:
    """Past scans, newest first."""
    scans = store.list_scans()
    if not scans:
        console.print("No scans yet. Run: shyena scan <path>")
        return
    table = Table(title="Shyena scans")
    table.add_column("Id", style="bold", no_wrap=True, min_width=12)
    table.add_column("Repo", overflow="ellipsis")
    table.add_column("Branch")
    table.add_column("Commit")
    table.add_column("Depth")
    table.add_column("Status")
    table.add_column("Gate")
    table.add_column("New")
    table.add_column("Started", no_wrap=True)
    for s in scans:
        gate = "-" if s.gate is None else ("[green]pass[/green]" if s.gate.passed else "[red]fail[/red]")
        table.add_row(
            s.id,
            Path(s.repo_root).name,
            s.branch or "-",
            (s.commit or "")[:8],
            s.depth,
            s.status,
            gate,
            str(len(s.by_status(FindingStatus.NEW))),
            (s.started_at or "")[:19].replace("T", " "),
        )
    console.print(table)


# ------------------------------------------------------------------------------ show


@app.command()
def show(
    scan_id: str = typer.Argument(..., help="Scan id (or unique prefix)."),
    everything: bool = typer.Option(False, "--all", help="Include recurring, accepted and false-positive findings."),
) -> None:
    """Details of one scan: gate, probe runs, findings."""
    try:
        run = store.load_scan(store.resolve_id(scan_id))
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[bold]{run.name}[/bold]  [dim]{run.id}[/dim]")
    console.print(f"  repo {run.repo_root}  branch {run.branch or '-'}  commit {(run.commit or '-')[:12]}  base {(run.base_commit or '-')[:12]}")
    console.print(f"  depth {run.depth}  policy {run.policy_name}  trigger {run.trigger}  status {run.status}  baseline {run.baseline_id or '-'}")
    if run.languages:
        console.print("  languages " + ", ".join(f"{k} ({v})" for k, v in list(run.languages.items())[:8]))
    probes = Table(title="Probe runs")
    for col in ("Probe", "Status", "Findings", "Seconds", "Note"):
        probes.add_column(col)
    for pr in run.probe_runs:
        colour = {"completed": "green", "skipped": "yellow", "error": "red"}.get(pr["status"], "white")
        probes.add_row(pr["probe"], f"[{colour}]{pr['status']}[/{colour}]", str(pr["findings"]), f"{pr['duration_s']:.1f}", pr.get("error") or pr.get("note") or "")
    console.print(probes)
    if run.metrics:
        console.print("  metrics " + ", ".join(f"{k}={v:g}" for k, v in sorted(run.metrics.items())))
    _print_summary(run)
    if everything:
        rest = [f for f in run.findings if f.status is not FindingStatus.NEW]
        if rest:
            _findings_table(rest, title="Other findings")
        if run.fixed:
            _findings_table(run.fixed, title="Fixed since baseline")


# ---------------------------------------------------------------------------- policy


@app.command("policy")
def policy_cmd(
    path: str = typer.Argument(".", help="Repository root."),
    depth: Optional[str] = typer.Option(None, "--depth", "-d"),
    trigger: str = typer.Option("pull_request", "--trigger", "-t"),
) -> None:
    """Show the effective policy and the depth profile a scan would use."""
    root = Path(path).resolve()
    try:
        policy = policy_mod.load(None, root)
        profile = depth_mod.resolve(policy.get("depth"), trigger=trigger, override=depth)
    except (ValueError, FileNotFoundError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[bold]Policy[/bold] from {policy.get('_source')}")
    printable = {k: v for k, v in policy.items() if not k.startswith("_")}
    console.print(yaml.safe_dump(printable, sort_keys=False).rstrip())
    table = Table(title=f"Depth profile: {profile.name} (trigger {trigger})")
    table.add_column("Dial")
    table.add_column("Setting")
    for key, value in profile.to_dict().items():
        if key == "name":
            continue
        table.add_row(key, json.dumps(value) if isinstance(value, (list, dict)) else str(value))
    console.print(table)


# ------------------------------------------------------------------------------ mark


@app.command()
def mark(
    fingerprint: str = typer.Argument(..., help="Finding fingerprint (or unique prefix from the latest scan)."),
    status: str = typer.Option(..., "--status", "-s", help="accepted | false_positive | open"),
    reason: str = typer.Option("", "--reason", "-r", help="Why (recorded with the decision)."),
    repo: str = typer.Option(".", "--repo", help="Repository root the finding belongs to."),
    by: str = typer.Option("", "--by", help="Who decided."),
) -> None:
    """Record a reviewer decision; it is keyed by fingerprint and survives across scans."""
    if status not in ("accepted", "false_positive", "open"):
        raise typer.BadParameter("status must be accepted, false_positive or open")
    if status != "open" and not reason:
        raise typer.BadParameter("--reason is required for accepted / false_positive")
    root = Path(repo).resolve()
    full = fingerprint
    if len(fingerprint) < 64:
        latest = store.find_baseline(root, base_commit=None, branch=None)
        matches = {f.id for f in (latest.findings if latest else []) if f.id.startswith(fingerprint)}
        if len(matches) != 1:
            raise typer.BadParameter(f"{fingerprint!r} matches {len(matches)} findings in the latest scan; give the full fingerprint")
        full = matches.pop()
    entry = store.set_state(root, full, status, reason, by)
    console.print(f"{short(full)} -> [bold]{entry.get('status', status)}[/bold]" + (f" ({reason})" if reason else ""))


def main() -> None:
    app()


if __name__ == "__main__":
    main()


# Keep the import used (repo module is handy for `python -m shyena` debugging sessions).
_ = repo_mod
