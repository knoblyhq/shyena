from datetime import date
from pathlib import Path

import pytest

from shyena import policy
from shyena.models import Category, CodeFinding, Component, FindingStatus, Location, Severity, Triage


def _f(category=Category.VULNERABILITY, severity=Severity.HIGH, status=FindingStatus.NEW, **kw) -> CodeFinding:
    base = dict(title=f"{category.value} {severity.value}", severity=severity, target="repo", probe="t", category=category, status=status, locations=[Location("a.py", 1)])
    base.update(kw)
    return CodeFinding(**base)


# --------------------------------------------------------------------------- load


def test_defaults_when_no_file(tmp_path: Path):
    p = policy.load(None, tmp_path)
    assert p["_source"] == "defaults"
    assert p["new_code"]["vulnerabilities"]["high"] == 0
    assert p["depth"]["on_pull_request"] == "standard"


def test_repo_file_overlays_defaults(tmp_path: Path):
    (tmp_path / ".shyena.yml").write_text("version: 1\nname: strict\nnew_code:\n  vulnerabilities:\n    medium: 0\n", encoding="utf-8")
    p = policy.load(None, tmp_path)
    assert p["name"] == "strict"
    assert p["new_code"]["vulnerabilities"] == {"critical": 0, "high": 0, "medium": 0}
    assert p["new_code"]["secrets"] == 0  # untouched default survives
    assert p["_source"].endswith(".shyena.yml")


def test_unsupported_version_rejected(tmp_path: Path):
    (tmp_path / ".shyena.yml").write_text("version: 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        policy.load(None, tmp_path)


def test_repo_policy_file_in_this_repo_loads():
    here = Path(__file__).resolve().parents[1]
    p = policy.load(here / ".shyena.yml")
    assert p["name"] == "default"
    assert p["depth"]["profiles"]["audit"]["extends"] == "deep"


# ------------------------------------------------------------------------- licences


@pytest.mark.parametrize(
    "expr,category",
    [
        ("MIT", "permissive"),
        ("Apache-2.0", "permissive"),
        ("GPL-3.0-only", "strong_copyleft"),
        ("GPL-2.0+", "strong_copyleft"),
        ("AGPL-3.0-or-later", "network_copyleft"),
        ("LGPL-2.1-only", "weak_copyleft"),
        ("MIT OR GPL-2.0-only", "permissive"),
        ("MIT AND GPL-2.0-only", "strong_copyleft"),
        ("(MIT OR Apache-2.0) AND MPL-2.0", "weak_copyleft"),
        ("MIT OR (GPL-2.0-only AND AGPL-3.0-only)", "permissive"),
        ("GPL-2.0-only WITH Classpath-exception-2.0", "strong_copyleft"),
        ("BUSL-1.1", "proprietary"),
        ("SomethingMadeUp", "unknown"),
        (None, "undeclared"),
        ("", "undeclared"),
    ],
)
def test_categorise_licence(expr, category):
    assert policy.categorise_licence(expr) == category


def test_licence_findings_follow_scope_and_exceptions():
    p = policy.load()
    p["licences"]["exceptions"] = [
        {"purl": "pkg:npm/gpl-tool", "reason": "build only", "expires": "2099-01-01"},
        {"purl": "pkg:npm/expired-tool", "reason": "was ok", "expires": "2020-01-01"},
    ]
    comps = [
        Component("pkg:pypi/agpl-lib@1", "agpl-lib", "1", "pypi", licence_declared="AGPL-3.0-only"),
        Component("pkg:npm/dev-agpl@1", "dev-agpl", "1", "npm", dev=True, licence_declared="AGPL-3.0-only"),
        Component("pkg:npm/dev-gpl@1", "dev-gpl", "1", "npm", dev=True, licence_declared="GPL-3.0-only"),
        Component("pkg:npm/mpl@1", "mpl", "1", "npm", licence_declared="MPL-2.0"),
        Component("pkg:npm/gpl-tool@2", "gpl-tool", "2", "npm", licence_declared="GPL-3.0-only"),
        Component("pkg:npm/expired-tool@2", "expired-tool", "2", "npm", licence_declared="GPL-3.0-only"),
        Component("pkg:npm/fine@1", "fine", "1", "npm", licence_declared="MIT"),
        Component("pkg:npm/nolicence@1", "nolicence", "1", "npm"),
        Component("pkg:npm/odd@1", "odd", "1", "npm", licence_declared="SomethingMadeUp"),
    ]
    findings = policy.licence_findings(p, comps, "repo", today=date(2026, 10, 14))
    by_name = {f.component.split("/")[-1].split("@")[0]: f for f in findings}
    assert by_name["agpl-lib"].rule_id == "shyena:licence.deny"
    assert by_name["agpl-lib"].severity is Severity.HIGH
    assert by_name["dev-agpl"].rule_id == "shyena:licence.deny"  # network copyleft denied even in dev
    assert "dev-gpl" not in by_name  # strong copyleft allowed in dev
    assert by_name["mpl"].rule_id == "shyena:licence.warn"
    assert by_name["mpl"].severity is Severity.LOW
    assert "gpl-tool" not in by_name  # live exception
    assert by_name["expired-tool"].rule_id == "shyena:licence.deny"  # expired exception ignored
    assert "fine" not in by_name
    assert by_name["nolicence"].rule_id == "shyena:licence.warn"  # no metadata: a warning, not a block
    assert "no licence metadata" in by_name["nolicence"].title
    assert by_name["odd"].rule_id == "shyena:licence.deny"  # unclassifiable licence text is denied
    assert all(f.category is Category.LICENCE for f in findings)


# ------------------------------------------------------------------------------ gate


def test_new_high_vulnerability_fails_gate():
    p = policy.load()
    gate = policy.evaluate(p, [_f()])
    assert not gate.passed
    assert gate.reasons == ["new vulnerabilities high: 1 > 0"]


def test_recurring_and_dismissed_findings_do_not_count():
    p = policy.load()
    gate = policy.evaluate(p, [_f(status=FindingStatus.RECURRING), _f(status=FindingStatus.ACCEPTED), _f(status=FindingStatus.FALSE_POSITIVE)])
    assert gate.passed


def test_medium_vulnerability_passes_default_gate():
    assert policy.evaluate(policy.load(), [_f(severity=Severity.MEDIUM)]).passed


def test_secrets_and_dependency_rules():
    p = policy.load()
    assert not policy.evaluate(p, [_f(Category.SECRET, Severity.MEDIUM)]).passed
    assert not policy.evaluate(p, [_f(Category.DEPENDENCY, Severity.CRITICAL, fix_available=False)]).passed
    assert not policy.evaluate(p, [_f(Category.DEPENDENCY, Severity.HIGH, fix_available=True)]).passed
    assert policy.evaluate(p, [_f(Category.DEPENDENCY, Severity.HIGH, fix_available=False)]).passed


def test_blocker_smell_and_metrics():
    p = policy.load()
    assert not policy.evaluate(p, [_f(Category.SMELL, Severity.HIGH)]).passed
    assert policy.evaluate(p, [_f(Category.SMELL, Severity.MEDIUM)]).passed
    gate = policy.evaluate(p, [], metrics={"coverage_percent": 70.0, "duplication_percent": 5.0, "complexity_max": 20.0})
    assert len(gate.reasons) == 3
    assert policy.evaluate(p, [], metrics={"coverage_percent": 90.0, "duplication_percent": 1.0, "complexity_max": 9.0}).passed


def test_licence_and_eol_rules_in_gate():
    p = policy.load()
    deny = _f(Category.LICENCE, Severity.HIGH, rule_id="shyena:licence.deny", title="x is GPL", locations=[])
    warn = _f(Category.LICENCE, Severity.LOW, rule_id="shyena:licence.warn", title="y is MPL", locations=[])
    eol = _f(Category.COMPATIBILITY, Severity.HIGH, rule_id="shyena:eol.runtime", title="python 3.7 is EOL")
    soon = _f(Category.COMPATIBILITY, Severity.MEDIUM, rule_id="shyena:eol.soon", title="node 18 ends soon")
    gate = policy.evaluate(p, [deny, warn, eol, soon])
    assert not gate.passed
    assert any("licence denied" in r for r in gate.reasons)
    assert any("end-of-life runtime" in r for r in gate.reasons)
    assert any("licence:" in w for w in gate.warnings)
    assert any("end-of-life soon" in w for w in gate.warnings)
    p["compatibility"]["fail_on_eol_runtime"] = False
    assert policy.evaluate(p, [warn, eol, soon]).passed


def test_ai_false_positive_demotes_but_never_blocks():
    p = policy.load()
    f = _f(triage=Triage("false_positive", 0.95))
    assert policy.evaluate(p, [f]).passed
    p["triage"]["demote_on_ai_false_positive"] = False
    assert not policy.evaluate(p, [f]).passed


def test_deep_taint_high_blocks_only_from_deep_pass():
    p = policy.load()
    taint = _f(Category.VULNERABILITY, Severity.MEDIUM, trace=[Location("a.py", 1, label="source"), Location("a.py", 2, label="sink")], scan_pass="deep")
    assert policy.evaluate(p, [taint]).passed  # medium
    taint.severity = Severity.HIGH
    gate = policy.evaluate(p, [taint])
    assert not gate.passed
    assert any("deep-pass taint" in r for r in gate.reasons)
