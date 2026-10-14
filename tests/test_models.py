from pathlib import Path

from shyena import fingerprint
from shyena.models import Category, CodeFinding, Component, FindingStatus, Location, ScanRun, Severity, Triage


def _finding(path="src/a.py", line=3, **kw) -> CodeFinding:
    base = dict(
        title="SQL built from input",
        severity=Severity.HIGH,
        target="repo",
        probe="semgrep",
        rule_id="semgrep:py.sqli",
        category=Category.VULNERABILITY,
        locations=[Location(path=path, start_line=line, snippet="  cur.execute(q)  ")],
    )
    base.update(kw)
    return CodeFinding(**base)


def test_round_trip_keeps_every_field():
    f = _finding(
        trace=[Location("src/a.py", 1, label="source"), Location("src/a.py", 3, label="sink")],
        component="pkg:pypi/requests@2.31.0",
        licence="Apache-2.0",
        triage=Triage("true_positive", 0.9, "reachable", "parametrise", "claude", "v1", 120),
        introduced_commit="abc1234",
        cwe="CWE-89",
        status=FindingStatus.RECURRING,
    )
    d = f.to_dict()
    g = CodeFinding.from_dict(d)
    assert g.to_dict() == d
    assert g.id == f.id
    assert g.trace[1].label == "sink"
    assert g.triage.verdict == "true_positive"
    assert g.status is FindingStatus.RECURRING


def test_core_fields_still_serialise_for_the_grc_core():
    d = _finding().to_dict()
    for key in ("id", "title", "severity", "target", "probe", "description", "evidence", "remediation", "references", "cwe", "cve"):
        assert key in d


def test_fingerprint_survives_line_shift_and_reformatting(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\nq = build()\ncur.execute(q)\nprint(1)\n", encoding="utf-8")
    first = fingerprint.enrich(_finding(line=3), tmp_path)

    # Two lines inserted above, indentation and trailing whitespace changed.
    (src / "a.py").write_text("# header\n\nx = 1\n  q   =  build()   \n\tcur.execute(q)\nprint(1)\n", encoding="utf-8")
    moved = fingerprint.enrich(_finding(line=5), tmp_path)
    assert moved.id == first.id

    (src / "a.py").write_text("x = 1\nq = build()\ncur.execute(other)\nprint(1)\n", encoding="utf-8")
    changed = fingerprint.enrich(_finding(line=3), tmp_path)
    assert changed.id != first.id


def test_dependency_fingerprint_ignores_version():
    a = _finding(category=Category.DEPENDENCY, component="pkg:npm/lodash@4.17.20", cve="CVE-2021-23337", rule_id="grype:CVE-2021-23337", locations=[])
    b = _finding(category=Category.DEPENDENCY, component="pkg:npm/lodash@4.17.21", cve="CVE-2021-23337", rule_id="grype:CVE-2021-23337", locations=[])
    c = _finding(category=Category.DEPENDENCY, component="pkg:npm/lodash@4.17.21", cve="CVE-2020-8203", rule_id="grype:CVE-2020-8203", locations=[])
    assert a.id == b.id
    assert a.id != c.id


def test_scoped_npm_purl_strips_only_the_version():
    assert fingerprint.purl_without_version("pkg:npm/@types/node@20.1.0") == "pkg:npm/@types/node"
    assert fingerprint.purl_without_version("pkg:pypi/requests") == "pkg:pypi/requests"


def test_secret_fingerprint_uses_the_hash_not_the_value():
    a = _finding(category=Category.SECRET, rule_id="gitleaks:aws-key", evidence="sha256:abc", locations=[Location("cfg.py", 1)])
    b = _finding(category=Category.SECRET, rule_id="gitleaks:aws-key", evidence="sha256:abc", locations=[Location("other.py", 9)])
    c = _finding(category=Category.SECRET, rule_id="gitleaks:aws-key", evidence="sha256:def", locations=[Location("cfg.py", 1)])
    assert a.id == b.id
    assert a.id != c.id


def test_scanrun_round_trip():
    run = ScanRun(id="abc", name="r", repo_root="/r", findings=[_finding()], components=[Component("pkg:pypi/x@1", "x", "1", "pypi")], metrics={"nloc": 10.0})
    run.mark_started()
    run.mark_finished("completed")
    d = run.to_dict()
    back = ScanRun.from_dict(d)
    assert back.to_dict() == d
    assert back.severity_counts()["high"] == 1
    assert back.category_counts()["vulnerability"] == 1
