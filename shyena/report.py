"""Reports: the SARIF bundle, a JSON summary for CI and pull-request decoration, a
Markdown report, plus the GRC core's own JSON / Markdown so ``vapt report`` works."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vapt.core.models import TestInstance
from vapt.reporting import report as core_report

from shyena import __version__, sarif, store
from shyena.fingerprint import short
from shyena.models import FindingStatus, ScanRun, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def summary(run: ScanRun) -> dict[str, Any]:
    """What a CI step or a PR comment needs, and nothing else."""
    new = run.by_status(FindingStatus.NEW)
    return {
        "id": run.id,
        "tool": f"shyena {__version__}",
        "repo": run.repo_root,
        "branch": run.branch,
        "commit": run.commit,
        "base_commit": run.base_commit,
        "depth": run.depth,
        "policy": run.policy_name,
        "status": run.status,
        "gate": run.gate.to_dict() if run.gate else None,
        "counts": {
            "new": len(new),
            "recurring": len(run.by_status(FindingStatus.RECURRING)),
            "fixed": len(run.fixed),
            "accepted": len(run.by_status(FindingStatus.ACCEPTED)),
            "false_positive": len(run.by_status(FindingStatus.FALSE_POSITIVE)),
            "by_severity": run.severity_counts(),
            "by_category": run.category_counts(),
            "components": len(run.components),
        },
        "metrics": run.metrics,
        "probe_runs": run.probe_runs,
        "new_findings": [
            {
                "fingerprint": f.id,
                "rule_id": f.rule_id,
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "path": f.primary.path if f.primary else None,
                "line": f.primary.start_line if f.primary else None,
                "component": f.component,
                "cwe": f.cwe,
                "cve": f.cve,
                "introduced_commit": f.introduced_commit,
            }
            for f in sorted(new, key=lambda x: x.severity.rank, reverse=True)
        ],
    }


def markdown(run: ScanRun) -> str:
    gate = run.gate
    lines: list[str] = []
    lines.append(f"# Shyena scan — {run.name}")
    lines.append("")
    verdict = "PASS" if gate and gate.passed else "FAIL"
    lines.append(f"**Gate: {verdict}**  ·  scan `{run.id}`  ·  depth `{run.depth}`  ·  policy `{run.policy_name}`")
    lines.append("")
    lines.append(f"- Repository: `{run.repo_root}`")
    lines.append(f"- Branch / commit: {run.branch or '-'} / `{(run.commit or '-')[:12]}`" + (f" (base `{run.base_commit[:12]}`)" if run.base_commit else ""))
    if run.changed_files:
        lines.append(f"- Changed files: {len(run.changed_files)}")
    if run.languages:
        lines.append("- Languages: " + ", ".join(f"{k} ({v})" for k, v in list(run.languages.items())[:8]))
    if run.started_at:
        lines.append(f"- Started: {run.started_at}" + (f" · finished: {run.finished_at}" if run.finished_at else ""))
    if run.baseline_id:
        lines.append(f"- Baseline scan: `{run.baseline_id}`")
    lines.append("")
    if gate:
        if gate.reasons:
            lines.append("## Why the gate failed")
            lines.extend(f"- {r}" for r in gate.reasons)
            lines.append("")
        if gate.warnings:
            lines.append("## Warnings")
            lines.extend(f"- {w}" for w in gate.warnings)
            lines.append("")

    counts = run.severity_counts()
    lines.append("## Findings")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("| --- | --- |")
    for status in FindingStatus:
        n = len(run.fixed) if status is FindingStatus.FIXED else len(run.by_status(status))
        lines.append(f"| {status.value} | {n} |")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in _ORDER:
        lines.append(f"| {sev.value} | {counts[sev.value]} |")
    lines.append("")

    new = sorted(run.by_status(FindingStatus.NEW), key=lambda x: x.severity.rank, reverse=True)
    if new:
        lines.append("### New")
        lines.append("")
        lines.append("| Sev | Dimension | Rule | Finding | Where | Fingerprint |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for f in new:
            loc = f.primary
            where = f"`{loc.path}:{loc.start_line}`" if loc and loc.start_line else (f"`{loc.path}`" if loc else (f"`{f.component}`" if f.component else ""))
            lines.append(f"| {f.severity.value} | {f.category.value} | `{f.rule_id}` | {f.title.replace('|', '/')} | {where} | `{short(f.id)}` |")
        lines.append("")
        for f in new:
            lines.append(f"#### {f.title}")
            lines.append("")
            if f.description:
                lines.append(f.description.strip())
                lines.append("")
            meta = [f"severity **{f.severity.value}**", f"rule `{f.rule_id}`"]
            if f.cwe:
                meta.append(f"{f.cwe}")
            if f.cve:
                meta.append(f"{f.cve}")
            if f.introduced_commit:
                meta.append(f"introduced in `{f.introduced_commit[:12]}`")
            if f.confidence:
                meta.append(f"confidence {f.confidence.value}")
            lines.append("- " + " · ".join(meta))
            if f.trace:
                lines.append("- Dataflow: " + " → ".join(f"`{t.path}:{t.start_line}`" for t in f.trace))
            if f.remediation:
                lines.append(f"- Fix: {f.remediation.strip()}")
            if f.triage:
                lines.append(f"- AI triage: {f.triage.verdict} ({f.triage.confidence:.0%}) — {f.triage.explanation}")
            if f.references:
                lines.append("- References: " + ", ".join(f.references[:3]))
            lines.append("")

    if run.fixed:
        lines.append("### Fixed since baseline")
        lines.append("")
        lines.extend(f"- {f.title} (`{short(f.id)}`)" for f in run.fixed)
        lines.append("")

    if run.metrics:
        lines.append("## Metrics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        for k, v in sorted(run.metrics.items()):
            lines.append(f"| {k} | {v:g} |")
        lines.append("")

    if run.components:
        lines.append("## Components")
        lines.append("")
        lines.append(f"{len(run.components)} packages in the SBOM; {sum(1 for c in run.components if c.dev)} development-only.")
        lines.append("")

    lines.append("## Engines")
    lines.append("")
    lines.append("| Probe | Status | Findings | Seconds | Note |")
    lines.append("| --- | --- | --- | --- | --- |")
    for pr in run.probe_runs:
        lines.append(f"| {pr['probe']} | {pr['status']} | {pr['findings']} | {pr['duration_s']:.1f} | {(pr.get('error') or pr.get('note') or '').replace('|', '/')} |")
    lines.append("")
    lines.append(f"_Depth profile `{run.depth}`: scope {run.depth_profile.get('scope')}, taint {run.depth_profile.get('taint_mode')}, dependencies {run.depth_profile.get('dependencies')}, secrets {run.depth_profile.get('secrets_history')}, AI triage {run.depth_profile.get('ai_triage')}._")
    lines.append("")
    return "\n".join(lines)


def write_all(run: ScanRun, instance: TestInstance) -> dict[str, Path]:
    directory = store.scan_dir(run.id)
    directory.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    # The core writes findings.json and its own report.md; ours goes last so
    # report.md is the Shyena report (the core re-renders on demand anyway).
    try:
        paths.update({f"core_{k}": v for k, v in core_report.write_reports(instance).items()})
    except Exception:  # noqa: BLE001 — the core's reports are a convenience, never a scan failure
        pass
    paths["sarif"] = sarif.write(sarif.to_sarif(instance.results, tool_version=__version__, scan_id=run.id), directory / "results.sarif")
    paths["summary"] = directory / "summary.json"
    paths["summary"].write_text(json.dumps(summary(run), indent=2), encoding="utf-8")
    paths["markdown"] = directory / "report.md"
    paths["markdown"].write_text(markdown(run), encoding="utf-8")
    return paths
