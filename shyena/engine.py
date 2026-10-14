"""The scan pipeline.

1. Checkout and fingerprint the tree (commit, base, changed files, languages).
2. Inventory: SBOM and manifest detection run first.
3. Fast pass: every selected probe, each isolated, each checkpointed.
4. Normalise: every result is a ``CodeFinding`` with a stable fingerprint.
5. Fingerprint and classify: new / recurring / fixed against the baseline scan,
   reviewer decisions applied.
6. Triage with AI (the configured provider; null in Phase 0).
7. Evaluate the gate.
8. Report: SARIF bundle, JSON summary, Markdown; the GRC core's own reports too.
9. Deep pass: engines marked ``deep`` run in the same loop when the profile asks for
   them (asynchronous scheduling arrives with the server in Phase 1).

Every scan is also a GRC ``TestInstance`` (scope ``code``, target ``repo``) saved under
the same id, so the core's ``list`` / ``show`` / ``report`` / dashboard see it.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vapt.core import instance as core_store
from vapt.core.models import InstanceStatus, ProbeResult, ProbeStatus, Scope, Target, TestInstance

from shyena import __version__, classify, fingerprint, report
from shyena import depth as depth_mod
from shyena import policy as policy_mod
from shyena import repo as repo_mod
from shyena import store
from shyena import triage as triage_mod
from shyena.models import CodeFinding, FindingStatus, ScanRun
from shyena.probes import probes_for
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext

#: Event callback ``(event_name, payload)`` for live progress in the CLI.
EventHook = Callable[[str, dict[str, Any]], None]

#: Cap on ``git blame`` lookups per scan, to keep the fast pass fast.
MAX_BLAME_LOOKUPS = 200


def _emit(hook: EventHook | None, event: str, **payload: Any) -> None:
    """Progress is a courtesy: a failing hook (say, a console that cannot encode a
    glyph) must never abort or corrupt a scan."""
    if hook is None:
        return
    try:
        hook(event, payload)
    except Exception:  # noqa: BLE001
        pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _probe_run_record(result: ProbeResult) -> dict[str, Any]:
    return {
        "probe": result.probe,
        "status": result.status.value,
        "duration_s": round(result.duration_s, 3),
        "findings": len(result.findings),
        "error": result.error,
        "note": result.note,
    }


def scan(
    path: str | Path,
    *,
    depth: str | None = None,
    base: str | None = None,
    policy_path: str | Path | None = None,
    baseline_id: str | None = None,
    trigger: str = "pull_request",
    name: str | None = None,
    on_event: EventHook | None = None,
    extra_probes: list[CodeProbe] | None = None,
) -> ScanRun:
    """Run one scan of the repository at ``path`` and persist it. Returns the ``ScanRun``.

    A crash after the run is created marks both the GRC instance and the scan as
    failed (with the error) before re-raising, so nothing is left ``running``."""
    state: dict[str, Any] = {}
    try:
        return _scan(path, depth=depth, base=base, policy_path=policy_path, baseline_id=baseline_id, trigger=trigger, name=name, on_event=on_event, extra_probes=extra_probes, _state=state)
    except Exception as exc:
        run: ScanRun | None = state.get("run")
        instance: TestInstance | None = state.get("instance")
        if instance is not None:
            instance.status = InstanceStatus.FAILED
            instance.finished_at = _utcnow()
            instance.config["error"] = f"{type(exc).__name__}: {exc}"
            core_store.save(instance)
        if run is not None:
            run.inventory["error"] = f"{type(exc).__name__}: {exc}"
            run.mark_finished("failed")
            store.save_scan(run)
        raise


def _scan(
    path: str | Path,
    *,
    depth: str | None,
    base: str | None,
    policy_path: str | Path | None,
    baseline_id: str | None,
    trigger: str,
    name: str | None,
    on_event: EventHook | None,
    extra_probes: list[CodeProbe] | None,
    _state: dict[str, Any],
) -> ScanRun:
    info = repo_mod.inspect(path, base)
    policy = policy_mod.load(policy_path, info.root)
    profile = depth_mod.resolve(policy.get("depth"), trigger=trigger, override=depth)

    # A first scan with nothing to diff against is an onboarding scan: whole tree.
    baseline = store.load_scan(baseline_id) if baseline_id else store.find_baseline(
        info.root, base_commit=info.base_commit, branch=info.branch
    )
    onboarding = baseline is None and info.base_commit is None and not profile.whole_tree
    if onboarding:
        profile.scope = "tree"

    target = Target.parse(str(info.root))
    instance = TestInstance(
        name=name or info.root.name,
        targets=[target],
        scopes=[Scope.CODE],
        authorized=True,
        config={
            "tool": "shyena",
            "version": __version__,
            "depth": profile.name,
            "commit": info.commit,
            "base_commit": info.base_commit,
            "branch": info.branch,
            "policy": policy.get("name", "default"),
            "trigger": trigger,
        },
    )
    instance.status = InstanceStatus.RUNNING
    instance.started_at = _utcnow()
    core_store.save(instance)
    _state["instance"] = instance

    run = ScanRun(
        id=instance.id,
        name=instance.name,
        repo_root=str(info.root),
        commit=info.commit,
        base_commit=info.base_commit,
        branch=info.branch,
        changed_files=info.changed_files,
        languages=info.languages,
        manifests=info.manifests,
        depth=profile.name,
        depth_profile=profile.to_dict(),
        policy_name=str(policy.get("name", "default")),
        trigger=trigger,
        scan_pass="deep" if profile.runs_deep else "fast",
        baseline_id=baseline.id if baseline else None,
    )
    run.inventory["policy_source"] = policy.get("_source", "defaults")
    if onboarding:
        run.inventory["onboarding"] = True
    run.mark_started()
    store.save_scan(run)
    _state["run"] = run

    workdir = store.workdir_for(run.id)
    ctx = ScanContext(repo=info, depth=profile, policy=policy, target=target.raw)

    wanted = probes_for(profile, available_only=False)
    selected = probes_for(profile) + list(extra_probes or [])
    _emit(
        on_event,
        "run_start",
        scan_id=run.id,
        repo=str(info.root),
        depth=profile.name,
        probes=[p.name for p in selected],
        changed_files=len(info.changed_files),
        onboarding=onboarding,
    )

    # Probes the profile wanted but cannot run: say so in the record.
    for probe in wanted:
        if probe in selected or any(p.name == probe.name for p in selected):
            continue
        note = f"not installed — {probe.install_hint}" if probe.install_hint else "not installed"
        result = ProbeResult(probe=probe.name, target=target.raw, status=ProbeStatus.SKIPPED, note=note)
        instance.results.append(result)
        run.probe_runs.append(_probe_run_record(result))
        _emit(on_event, "probe_skipped", probe=probe.name, note=note)
    for probe_name, reason in profile.disabled_probes.items():
        result = ProbeResult(probe=probe_name, target=target.raw, status=ProbeStatus.SKIPPED, note=f"disabled in policy: {reason}")
        instance.results.append(result)
        run.probe_runs.append(_probe_run_record(result))

    started = time.monotonic()
    budget_s = profile.budget_minutes * 60 if profile.budget_minutes else None
    errors = False
    for probe in selected:
        if budget_s is not None and time.monotonic() - started > budget_s:
            result = ProbeResult(probe=probe.name, target=target.raw, status=ProbeStatus.SKIPPED, note="time budget exhausted")
            instance.results.append(result)
            run.probe_runs.append(_probe_run_record(result))
            _emit(on_event, "probe_skipped", probe=probe.name, note=result.note)
            continue
        result, output = _run_probe(probe, ctx, workdir, on_event)
        instance.results.append(result)
        run.probe_runs.append(_probe_run_record(result))
        if output is not None:
            run.metrics.update(output.metrics)
            if output.components:
                ctx.components.extend(output.components)
                run.components.extend(output.components)
            if output.inventory:
                run.inventory.update(output.inventory)
                ctx.inventory.update(output.inventory)
                if output.inventory.get("sbom_path"):
                    ctx.sbom_path = Path(output.inventory["sbom_path"])
        if result.status is ProbeStatus.ERROR:
            errors = True
        core_store.save(instance)  # checkpoint after each probe
        store.save_scan(run)

    # Our policy engine over the SBOM.
    licence_findings = policy_mod.licence_findings(policy, run.components, target.raw)
    licence_result = ProbeResult(
        probe="licence-policy",
        target=target.raw,
        status=ProbeStatus.COMPLETED if run.components else ProbeStatus.SKIPPED,
        findings=licence_findings,
        note=f"{len(run.components)} components checked" if run.components else "no SBOM components",
    )
    instance.results.append(licence_result)
    run.probe_runs.append(_probe_run_record(licence_result))

    # Normalise and fingerprint.
    findings: list[CodeFinding] = []
    seen: set[str] = set()
    for result in instance.results:
        for f in result.findings:
            cf = f if isinstance(f, CodeFinding) else CodeFinding.from_dict(f.to_dict())
            fingerprint.enrich(cf, info.root)
            if cf.id in seen:
                continue
            seen.add(cf.id)
            findings.append(cf)

    # Classify against the baseline and reviewer decisions.
    states = store.load_states(info.root)
    findings, fixed = classify.classify(findings, baseline.findings if baseline else [], states)
    changed_lines = None
    if info.is_git and not onboarding and (info.base_commit or baseline is not None):
        changed_lines = repo_mod.changed_lines(info.root, info.base_commit)
    gate_findings = [f for f in findings if classify.gate_eligible(f, changed_lines)]

    # Attribute new code findings to the commit that introduced them.
    if info.is_git:
        lookups = 0
        for f in findings:
            if f.status is not FindingStatus.NEW or f.primary is None or not f.primary.start_line:
                continue
            if lookups >= MAX_BLAME_LOOKUPS:
                break
            f.introduced_commit = repo_mod.blame_commit(info.root, f.primary.path, f.primary.start_line)
            lookups += 1

    # Triage with AI, then the gate (AI may demote, never block).
    triager = triage_mod.select(profile)
    candidates = triage_mod.candidates(gate_findings, profile, str(policy.get("triage", {}).get("ai_threshold", "medium")))
    triaged = triage_mod.run(triager, candidates, {"repo": str(info.root), "commit": info.commit})
    triage_result = ProbeResult(
        probe=f"triage:{triager.name}",
        target=target.raw,
        status=ProbeStatus.COMPLETED if triager.name != "null" else ProbeStatus.SKIPPED,
        note=f"{triaged} of {len(candidates)} candidates triaged" if triager.name != "null" else f"AI triage {profile.ai_triage}; provider null",
    )
    run.probe_runs.append(_probe_run_record(triage_result))

    run.gate = policy_mod.evaluate(policy, gate_findings, run.metrics, run.components)
    run.findings = findings
    run.fixed = fixed

    # Finish and report.
    instance.status = InstanceStatus.FAILED if errors else InstanceStatus.COMPLETED
    instance.finished_at = _utcnow()
    core_store.save(instance)
    run.mark_finished("completed_with_errors" if errors else "completed")
    store.save_scan(run)
    report.write_all(run, instance)

    _emit(
        on_event,
        "run_done",
        scan_id=run.id,
        status=run.status,
        gate=run.gate.passed,
        new=len(run.by_status(FindingStatus.NEW)),
        recurring=len(run.by_status(FindingStatus.RECURRING)),
        fixed=len(run.fixed),
        findings=len(run.findings),
    )
    return run


def _run_probe(probe: CodeProbe, ctx: ScanContext, workdir: Path, on_event: EventHook | None) -> tuple[ProbeResult, ProbeOutput | None]:
    probe.context = ctx
    _emit(on_event, "probe_start", probe=probe.name)
    started = time.monotonic()
    output: ProbeOutput | None = None
    try:
        output = probe.scan(ctx, workdir)
        did_something = bool(output.findings or output.metrics or output.components or output.inventory)
        status = ProbeStatus.COMPLETED if did_something or not output.note else ProbeStatus.SKIPPED
        for f in output.findings:
            f.scan_pass = probe.scan_pass
        result = ProbeResult(
            probe=probe.name,
            target=ctx.target,
            status=status,
            findings=list(output.findings),
            note=output.note,
            duration_s=time.monotonic() - started,
        )
    except subprocess.TimeoutExpired as exc:
        result = ProbeResult(probe=probe.name, target=ctx.target, status=ProbeStatus.ERROR, error=f"timeout after {exc.timeout:.0f}s", duration_s=time.monotonic() - started)
    except Exception as exc:  # noqa: BLE001 — the engine must survive any probe failure
        result = ProbeResult(probe=probe.name, target=ctx.target, status=ProbeStatus.ERROR, error=f"{type(exc).__name__}: {exc}", duration_s=time.monotonic() - started)
    finally:
        probe.context = None
    _emit(on_event, "probe_done", probe=probe.name, status=result.status.value, findings=len(result.findings), error=result.error, note=result.note)
    return result, output
