"""End-to-end scans on a throwaway git repository with no external engines installed."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner
from vapt.core import instance as core_store
from vapt.core.models import Scope, TargetType

from shyena import classify, engine, store
from shyena import repo as repo_mod
from shyena.cli import app
from shyena.models import Category, CodeFinding, FindingStatus, Location, Severity
from shyena.probes.base import ProbeOutput, PythonCodeProbe
from tests.conftest import commit_all


class FakeSast(PythonCodeProbe):
    """Reports one high finding on app.py line 4 — or nothing when told to."""

    name = "fake-sast"
    category = Category.VULNERABILITY

    def __init__(self, report: bool = True):
        self.report = report

    def scan(self, ctx, workdir):
        if not self.report:
            return ProbeOutput(note="nothing to report")
        return ProbeOutput(
            findings=[
                CodeFinding(
                    title="OS command built from input",
                    severity=Severity.HIGH,
                    target=ctx.target,
                    probe=self.name,
                    rule_id="fake:os-command",
                    category=Category.VULNERABILITY,
                    locations=[Location("app.py", 4, snippet="return os.system(cmd)")],
                    cwe="CWE-78",
                )
            ],
            metrics={"fake": 1.0},
        )


def test_first_scan_completes_with_only_pure_python_probes(git_repo: Path):
    events: list[str] = []
    run = engine.scan(git_repo, on_event=lambda e, p: events.append(e))

    assert run.status == "completed"
    assert run.inventory.get("onboarding") is True
    assert run.depth == "standard" and run.depth_profile["scope"] == "tree"
    assert run.commit and run.branch == "main"
    assert run.languages.get("python") == 1
    assert "requirements.txt" in run.manifests
    by_probe = {p["probe"]: p for p in run.probe_runs}
    assert by_probe["manifests"]["status"] == "completed"
    assert run.inventory["runtimes"][0] == {"product": "python", "cycle": "3.12", "source": ".python-version"}
    for missing in ("syft", "semgrep", "grype", "trivy", "gitleaks", "lizard"):
        assert by_probe[missing]["status"] == "skipped", missing
        assert "not installed" in by_probe[missing]["note"]
    assert by_probe["licence-policy"]["status"] == "skipped"
    assert by_probe["triage:null"]["status"] == "skipped"
    assert run.gate is not None and run.gate.passed
    assert events[0] == "run_start" and events[-1] == "run_done"

    run_dir = store.scan_dir(run.id)
    for name in ("instance.json", "scan.json", "results.sarif", "summary.json", "report.md"):
        assert (run_dir / name).exists(), name
    assert (run_dir / "report.md").read_text("utf-8").startswith("# Shyena scan")
    assert (run_dir / "findings.json").exists()  # the GRC core's own report
    summary = json.loads((run_dir / "summary.json").read_text("utf-8"))
    assert summary["gate"]["passed"] is True and summary["id"] == run.id
    bundle = json.loads((run_dir / "results.sarif").read_text("utf-8"))
    assert bundle["version"] == "2.1.0" and {r["tool"]["driver"]["name"] for r in bundle["runs"]} >= {"manifests", "licence-policy"}

    # The GRC core sees the same scan as a test instance in the ``code`` scope.
    inst = core_store.load(run.id)
    assert inst.scopes == [Scope.CODE]
    assert inst.targets[0].type is TargetType.REPO
    assert inst.config["tool"] == "shyena"


def test_lifecycle_new_recurring_accepted_fixed(git_repo: Path):
    first = engine.scan(git_repo, extra_probes=[FakeSast()])
    (new,) = first.by_status(FindingStatus.NEW)
    assert new.rule_id == "fake:os-command"
    assert new.introduced_commit == first.commit
    assert new.context  # filled from the working tree
    assert not first.gate.passed and first.gate.reasons == ["new vulnerabilities high: 1 > 0"]
    assert first.metrics["fake"] == 1.0

    second = engine.scan(git_repo, extra_probes=[FakeSast()])
    assert second.baseline_id == first.id
    (rec,) = second.findings
    assert rec.status is FindingStatus.RECURRING and rec.id == new.id
    assert second.gate.passed
    assert second.depth_profile["scope"] == "changed_plus_importers"  # no longer onboarding

    store.set_state(git_repo, new.id, "accepted", "legacy, tracked in JIRA-1", "reviewer")
    third = engine.scan(git_repo, extra_probes=[FakeSast()])
    assert third.findings[0].status is FindingStatus.ACCEPTED
    assert third.gate.passed

    fourth = engine.scan(git_repo, extra_probes=[FakeSast(report=False)])
    assert fourth.findings == []
    assert [f.id for f in fourth.fixed] == [new.id]
    assert fourth.fixed[0].status is FindingStatus.FIXED

    assert [s.id for s in store.list_scans()][0] == fourth.id
    assert store.resolve_id(fourth.id[:6]) == fourth.id


def test_only_findings_on_changed_lines_gate_a_pull_request(git_repo: Path):
    base = repo_mod.git(git_repo, "rev-parse", "HEAD")
    # A baseline exists for the base commit, with the finding already present at line 4.
    engine.scan(git_repo, extra_probes=[FakeSast()])

    # The change touches other lines; the recurring finding must not block it.
    (git_repo / "app.py").write_text("import os\n\ndef run(cmd):\n    return os.system(cmd)\n\nVERSION = 1\n\nprint('new line')\n", encoding="utf-8")
    commit_all(git_repo, "add a print")
    pr = engine.scan(git_repo, base=base, extra_probes=[FakeSast()])
    assert pr.base_commit == base
    assert pr.changed_files == ["app.py"]
    assert pr.findings[0].status is FindingStatus.RECURRING
    assert pr.gate.passed

    lines = repo_mod.changed_lines(git_repo, base)
    assert lines == {"app.py": {7, 8}}

    # The same finding, had it been new, would not count either: line 4 is untouched.
    fresh = CodeFinding(title="t", severity=Severity.HIGH, target="r", probe="p", locations=[Location("app.py", 4)])
    assert not classify.gate_eligible(fresh, lines)


def test_gate_eligibility_by_line_and_category():
    code = CodeFinding(title="t", severity=Severity.HIGH, target="r", probe="p", locations=[Location("a.py", 10, end_line=12)])
    dep = CodeFinding(title="d", severity=Severity.HIGH, target="r", probe="p", category=Category.DEPENDENCY, component="pkg:npm/x@1")
    assert classify.gate_eligible(code, None)
    assert classify.gate_eligible(code, {"a.py": {11}})
    assert not classify.gate_eligible(code, {"a.py": {2}})
    assert not classify.gate_eligible(code, {"b.py": {10}})
    assert classify.gate_eligible(dep, {"b.py": {1}})  # lineless categories always count
    code.status = FindingStatus.RECURRING
    assert not classify.gate_eligible(code, None)


def test_plain_directory_without_git(tmp_path: Path):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "main.go").write_text("package main\n", encoding="utf-8")
    (root / "go.mod").write_text("module x\n\ngo 1.21\n", encoding="utf-8")
    run = engine.scan(root, depth="quick")
    assert run.status == "completed" and run.commit is None and run.branch is None
    assert run.inventory["runtimes"] == [{"product": "go", "cycle": "1.21", "source": "go.mod"}]
    assert run.gate.passed


def test_cli_scan_tools_list_show(git_repo: Path):
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(git_repo), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["gate"]["passed"] is True
    scan_id = payload["id"]

    assert runner.invoke(app, ["tools"]).exit_code == 0
    listed = runner.invoke(app, ["list"])
    assert listed.exit_code == 0 and scan_id[:8] in listed.output
    shown = runner.invoke(app, ["show", scan_id[:6], "--all"])
    assert shown.exit_code == 0 and "manifests" in shown.output
    pol = runner.invoke(app, ["policy", str(git_repo), "--depth", "audit"])
    assert pol.exit_code == 0 and "per_file" in pol.output
    bad = runner.invoke(app, ["scan", str(git_repo), "--depth", "bogus"])
    assert bad.exit_code != 0


def test_cli_gate_failure_exit_code(git_repo: Path, monkeypatch):
    monkeypatch.setattr(engine, "probes_for", lambda profile, available_only=True: [FakeSast()] if available_only else [])
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(git_repo)])
    assert result.exit_code == 1, result.output
    assert "FAIL" in result.output and "os-command" in result.output or "OS command" in result.output
    ok = runner.invoke(app, ["scan", str(git_repo), "--no-fail"])
    assert ok.exit_code == 0
