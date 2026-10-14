"""Runs the installed engines for real on a tiny vulnerable repository.

Skipped when a binary is missing, so the suite passes on a bare machine; on a
developer machine with Semgrep and Lizard it proves the adapters against live output.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from shyena import engine
from shyena.models import Category, FindingStatus, Severity
from tests.conftest import commit_all, git

VULN_PHP = """<?php
$conn = new mysqli("h", "u", "p", "d");
$id = $_GET['id'];
$res = $conn->query("SELECT * FROM users WHERE id = " . $id);
$safe = intval($_GET['page']);
$res2 = $conn->query("SELECT * FROM posts LIMIT " . $safe);
$slug = $_GET['slug'];
if (preg_match('/^[a-z0-9_-]+$/i', $slug)) {
    $doc = file_get_contents(__DIR__ . '/docs/' . $slug . '.json');
}
echo $_POST['name'];
function knotty($a) {
    if ($a == 1) { return 1; } if ($a == 2) { return 2; } if ($a == 3) { return 3; } if ($a == 4) { return 4; }
    if ($a == 5) { return 5; } if ($a == 6) { return 6; } if ($a == 7) { return 7; } if ($a == 8) { return 8; }
    if ($a == 9) { return 9; } if ($a == 10) { return 10; } if ($a == 11) { return 11; } if ($a == 12) { return 12; }
    if ($a == 13) { return 13; } if ($a == 14) { return 14; } if ($a == 15) { return 15; } if ($a == 16) { return 16; }
    return 0;
}
"""


@pytest.fixture
def vuln_repo(tmp_path) -> Path:
    root = tmp_path / "vuln"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "index.php").write_text(VULN_PHP, encoding="utf-8")
    commit_all(root, "vulnerable app")
    return root


@pytest.mark.real_tools
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_adapter_on_live_output(vuln_repo: Path):
    run = engine.scan(vuln_repo, depth="quick")
    semgrep_run = next(p for p in run.probe_runs if p["probe"] == "semgrep")
    assert semgrep_run["status"] == "completed", semgrep_run
    hits = {f.rule_id: f for f in run.findings if f.probe == "semgrep"}
    assert "semgrep:shyena.php.sqli-taint" in hits
    assert "semgrep:shyena.php.xss-echo-request" in hits
    assert "semgrep:shyena.php.file-inclusion-taint" not in hits  # preg_match sanitised the slug
    sqli = hits["semgrep:shyena.php.sqli-taint"]
    assert sqli.severity is Severity.HIGH and sqli.category is Category.VULNERABILITY
    assert sqli.title.startswith("Request data reaches a SQL query")
    assert sqli.cwe == "CWE-89"
    assert sqli.primary.path == "index.php" and sqli.primary.start_line == 4
    assert sqli.status is FindingStatus.NEW and sqli.introduced_commit == run.commit
    assert not run.gate.passed


@pytest.mark.real_tools
@pytest.mark.skipif(shutil.which("lizard") is None, reason="lizard not installed")
def test_lizard_adapter_on_live_output(vuln_repo: Path):
    run = engine.scan(vuln_repo, depth="deep")
    lizard_run = next(p for p in run.probe_runs if p["probe"] == "lizard")
    assert lizard_run["status"] == "completed", lizard_run
    assert run.metrics["functions"] >= 1
    assert run.metrics["complexity_max"] >= 16
    smells = [f for f in run.findings if f.rule_id == "lizard:complexity"]
    assert smells and smells[0].primary.path == "index.php" and "knotty" in smells[0].title
    assert any("complexity" in r for r in run.gate.reasons)
