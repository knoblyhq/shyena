from pathlib import Path

from vapt.core.models import ProbeResult, ProbeStatus

from shyena import sarif
from shyena.models import Category, Severity


def _doc(root: Path) -> dict:
    uri = (root / "src" / "a.py").as_uri()
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "py.sqli",
                                "shortDescription": {"text": "SQL injection"},
                                "helpUri": "https://example.com/sqli",
                                "properties": {"tags": ["security", "CWE-89: SQL Injection"], "security-severity": "9.1"},
                            },
                            {"id": "py.todo", "shortDescription": {"text": "TODO left"}, "defaultConfiguration": {"level": "note"}},
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py.sqli",
                        "level": "error",
                        "message": {"text": "User input reaches execute()"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 3, "endLine": 3, "startColumn": 5, "snippet": {"text": "cur.execute(q)"}},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 1}}}},
                                            {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 2}}}},
                                            {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 3}}}},
                                        ]
                                    }
                                ]
                            }
                        ],
                    },
                    {"ruleId": "py.todo", "message": {"text": "TODO"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./src/b.py"}, "region": {"startLine": 7}}}]},
                    {"ruleId": "py.other", "level": "warning", "message": {"text": "something"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/c.py"}, "region": {"startLine": 1}}}]},
                    {"ruleId": "py.suppressed", "kind": "pass", "message": {"text": "ignored"}},
                ],
            }
        ],
    }


def test_results_map_to_findings(tmp_path: Path):
    findings = sarif.findings_from_sarif(_doc(tmp_path), probe="semgrep", category=Category.VULNERABILITY, target="repo", repo_root=tmp_path)
    assert [f.rule_id for f in findings] == ["semgrep:py.sqli", "semgrep:py.todo", "semgrep:py.other"]
    sqli, todo, other = findings
    assert sqli.severity is Severity.CRITICAL  # security-severity 9.1 beats level=error
    assert sqli.title == "SQL injection"
    assert sqli.cwe == "CWE-89"
    assert sqli.references == ["https://example.com/sqli"]
    assert sqli.primary.path == "src/a.py"
    assert sqli.primary.start_line == 3
    assert sqli.primary.start_col == 5
    assert [t.label for t in sqli.trace] == ["source", "step", "sink"]
    assert todo.severity is Severity.LOW  # rule default level
    assert todo.primary.path == "src/b.py"
    assert other.severity is Severity.MEDIUM


def test_severity_bands():
    assert sarif.severity_from("error") is Severity.HIGH
    assert sarif.severity_from("warning") is Severity.MEDIUM
    assert sarif.severity_from("note") is Severity.LOW
    assert sarif.severity_from("none") is Severity.INFO
    assert sarif.severity_from("note", "7.5") is Severity.HIGH
    assert sarif.severity_from("error", "5.0") is Severity.MEDIUM
    assert sarif.severity_from("error", "2.0") is Severity.LOW
    assert sarif.severity_from("error", "not-a-number") is Severity.HIGH


def test_bundle_round_trips_fingerprint_and_status(tmp_path: Path):
    findings = sarif.findings_from_sarif(_doc(tmp_path), probe="semgrep", category=Category.VULNERABILITY, target="repo", repo_root=tmp_path)
    result = ProbeResult(probe="semgrep", target="repo", status=ProbeStatus.COMPLETED, findings=findings, duration_s=1.2)
    bundle = sarif.to_sarif([result], tool_version="0.0.1", scan_id="abc")
    assert bundle["version"] == "2.1.0"
    run = bundle["runs"][0]
    assert run["tool"]["driver"]["name"] == "semgrep"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"semgrep:py.sqli", "semgrep:py.todo", "semgrep:py.other"}
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["fingerprints"]["shyena/v1"] == findings[0].id
    assert first["properties"]["status"] == "new"
    assert first["properties"]["category"] == "vulnerability"
    assert len(first["codeFlows"][0]["threadFlows"][0]["locations"]) == 3

    back = sarif.findings_from_sarif(bundle, probe="semgrep", category=Category.VULNERABILITY, target="repo", repo_root=tmp_path)
    assert back[0].rule_id == "semgrep:py.sqli"
    assert back[0].id == findings[0].id
