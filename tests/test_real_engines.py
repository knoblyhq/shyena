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


SPRING_CONTROLLER = """package com.example.demo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private final JdbcTemplate jdbcTemplate;

    UserController(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }

    @GetMapping("/users")
    public Object byName(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    @GetMapping("/users/safe")
    public Object safe(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name);
    }
}
"""


SPRING_REPOSITORY = """package com.example.demo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class UserRepository {
    private final JdbcTemplate jdbcTemplate;
    UserRepository(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }
    Object byStatus(String status) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE status = '" + status + "'");
    }
}
"""


@pytest.mark.real_tools
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_on_a_spring_boot_change(tmp_path: Path):
    """A pull-request scan of a Spring Boot repo: the Java rules and the generic
    application.properties rules both run on just the changed files."""
    root = tmp_path / "boot"
    (root / "src/main/java/com/example/demo").mkdir(parents=True)
    (root / "src/main/resources").mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("demo\n", encoding="utf-8")
    commit_all(root, "init")
    git(root, "checkout", "-q", "-b", "feature")
    (root / "src/main/java/com/example/demo/UserController.java").write_text(SPRING_CONTROLLER, encoding="utf-8")
    (root / "src/main/java/com/example/demo/UserRepository.java").write_text(SPRING_REPOSITORY, encoding="utf-8")
    (root / "src/main/resources/mapper").mkdir()
    (root / "src/main/resources/mapper/UserMapper.xml").write_text(
        '<mapper namespace="x">\n  <select id="s">\n    SELECT * FROM users ORDER BY ${sort}\n  </select>\n</mapper>\n',
        encoding="utf-8",
    )
    (root / "src/main/resources/application.properties").write_text(
        "spring.datasource.password=Sup3rS3cret!\nmanagement.endpoints.web.exposure.include=*\n", encoding="utf-8"
    )
    commit_all(root, "users endpoint")

    run = engine.scan(root, depth="standard", base="main")
    semgrep_run = next(p for p in run.probe_runs if p["probe"] == "semgrep")
    assert semgrep_run["status"] == "completed", semgrep_run
    hits = {(f.rule_id, f.primary.path, f.primary.start_line) for f in run.findings if f.probe == "semgrep"}
    controller = "src/main/java/com/example/demo/UserController.java"
    props = "src/main/resources/application.properties"
    assert ("semgrep:shyena.java.sqli-taint", controller, 14) in hits
    assert not any(r == "semgrep:shyena.java.sqli-taint" and line == 19 for r, _, line in hits)
    assert ("semgrep:shyena.java.spring-secret-in-config", props, 1) in hits
    assert ("semgrep:shyena.java.spring-actuator-exposed", props, 2) in hits
    repo_file = "src/main/java/com/example/demo/UserRepository.java"
    assert ("semgrep:shyena.java.sql-non-constant", repo_file, 11) in hits
    assert ("semgrep:shyena.java.mybatis-dollar-substitution", "src/main/resources/mapper/UserMapper.xml", 3) in hits
    non_constant = next(f for f in run.findings if f.rule_id == "semgrep:shyena.java.sql-non-constant")
    assert non_constant.severity is Severity.MEDIUM  # informs; does not fail the gate on its own
    sqli = next(f for f in run.findings if f.rule_id == "semgrep:shyena.java.sqli-taint")
    assert sqli.severity is Severity.HIGH and sqli.cwe == "CWE-89" and sqli.status is FindingStatus.NEW
    assert not run.gate.passed
