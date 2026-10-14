"""Mapper tests for the engines, using canned native output (no binaries needed)."""

from __future__ import annotations

from pathlib import Path

from shyena.models import Category, CodeFinding, Location, Severity
from shyena.probes import all_probes, probes_for
from shyena.probes.gitleaks import scrub
from shyena.probes.grype import findings_from_grype_json
from shyena.probes.manifests import detect_runtimes
from shyena.probes.semgrep import categorise as semgrep_categorise
from shyena.probes.syft import components_from_cyclonedx
from shyena.probes.trivy import categorise as trivy_categorise
from shyena import depth


def test_registry_covers_the_phase_0_engines():
    names = [p.name for p in all_probes()]
    assert names == ["syft", "manifests", "semgrep", "grype", "trivy", "gitleaks", "lizard", "jscpd"]
    assert all(p.scopes[0].value == "code" and p.target_types[0].value == "repo" for p in all_probes())


def test_profile_selects_probes_by_pass_quality_and_disable():
    quick = depth.build("quick")
    names = {p.name for p in probes_for(quick, available_only=False)}
    assert "lizard" not in names and "jscpd" not in names  # blockers-only quality
    deep = depth.build("deep")
    names = {p.name for p in probes_for(deep, available_only=False)}
    assert {"lizard", "jscpd"} <= names
    deep.disabled_probes = {"jscpd": "too slow"}
    assert "jscpd" not in {p.name for p in probes_for(deep, available_only=False)}
    deep.compatibility = False
    assert "manifests" not in {p.name for p in probes_for(deep, available_only=False)}


def test_grype_json_mapper():
    doc = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2023-1234", "severity": "High", "description": "bad", "fix": {"versions": ["2.32.0"], "state": "fixed"}, "urls": ["https://nvd/x"], "cvss": [{"metrics": {"baseScore": 7.5}}]},
                "artifact": {"name": "requests", "version": "2.31.0", "type": "python", "purl": "pkg:pypi/requests@2.31.0", "locations": [{"path": "requirements.txt"}]},
            },
            {
                "vulnerability": {"id": "GHSA-abcd-efgh-ijkl", "severity": "Critical", "fix": {"versions": [], "state": "not-fixed"}},
                "artifact": {"name": "left-pad", "version": "1.0.0", "type": "npm", "purl": "pkg:npm/left-pad@1.0.0", "locations": []},
            },
        ]
    }
    a, b = findings_from_grype_json(doc, probe="grype", target="repo")
    assert a.category is Category.DEPENDENCY and a.severity is Severity.HIGH and a.fix_available is True
    assert a.cve == "CVE-2023-1234" and a.component == "pkg:pypi/requests@2.31.0" and a.primary.path == "requirements.txt"
    assert "2.32.0" in a.remediation and a.evidence == "cvss=7.5"
    assert b.severity is Severity.CRITICAL and b.fix_available is False and b.cve == "GHSA-abcd-efgh-ijkl"


def test_syft_cyclonedx_mapper():
    doc = {
        "components": [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0", "licenses": [{"license": {"id": "Apache-2.0"}}], "properties": [{"name": "syft:location:0:path", "value": "requirements.txt"}]},
            {"name": "jest", "version": "29.0.0", "purl": "pkg:npm/jest@29.0.0", "scope": "optional", "licenses": [{"expression": "MIT"}]},
            {"name": "no-purl", "version": "1"},
        ]
    }
    comps = components_from_cyclonedx(doc)
    assert [c.name for c in comps] == ["requests", "jest"]
    assert comps[0].ecosystem == "pypi" and comps[0].licence == "Apache-2.0" and comps[0].path == "requirements.txt" and not comps[0].dev
    assert comps[1].dev and comps[1].licence == "MIT"


def test_gitleaks_scrub_removes_the_secret_everywhere():
    f = CodeFinding(
        title="AWS key",
        severity=Severity.HIGH,
        target="repo",
        probe="gitleaks",
        rule_id="gitleaks:aws-access-key",
        category=Category.SECRET,
        description="AKIAIOSFODNN7EXAMPLE found",
        evidence="AKIAIOSFODNN7EXAMPLE",
        locations=[Location("cfg.py", 3, snippet="KEY='AKIAIOSFODNN7EXAMPLE'")],
        engine_raw={"locations": [{"physicalLocation": {"region": {"snippet": {"text": "AKIAIOSFODNN7EXAMPLE"}}}}]},
    )
    before = f.id
    scrub(f)
    blob = str(f.to_dict())
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert f.evidence.startswith("sha256:") and f.engine_raw is None and f.locations[0].snippet == ""
    assert f.id != before


def test_categorisers():
    assert semgrep_categorise("x", {}, {"tags": ["smell"]}) is Category.SMELL
    assert semgrep_categorise("x", {}, {"tags": ["deprecated"]}) is Category.COMPATIBILITY
    assert semgrep_categorise("x", {}, {"tags": ["security", "CWE-79"]}) is Category.VULNERABILITY
    assert trivy_categorise("CVE-2024-1", {}, {}) is Category.DEPENDENCY
    assert trivy_categorise("DS002", {}, {}) is Category.VULNERABILITY


def test_runtime_detection(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.11"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"engines": {"node": ">=18.0.0"}}', encoding="utf-8")
    (tmp_path / "composer.json").write_text('{"require": {"php": "^8.1"}}', encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\nFROM node:20-alpine AS build\n", encoding="utf-8")
    (tmp_path / ".nvmrc").write_text("v20.11.0\n", encoding="utf-8")
    found = detect_runtimes(tmp_path, ["pyproject.toml", "package.json", "composer.json", "Dockerfile"])
    pairs = {(r["product"], r["cycle"]) for r in found}
    assert pairs == {("python", "3.11"), ("nodejs", "18"), ("php", "8.1"), ("python", "3.9"), ("nodejs", "20")}
