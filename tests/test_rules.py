"""Proves our Semgrep rule set against annotated fixtures under ``tests/rules/semgrep``.

Fixture convention (Semgrep's own): a comment ``ruleid: <id>`` means the next line must
be reported by that rule; ``ok: <id>`` means it must not. Comments may be ``//``, ``#``
or ``<!-- -->``. Any finding of an annotated rule on a line not marked ``ruleid`` fails.

We do not use ``semgrep --test``: Semgrep's default ignore list skips ``tests/`` (so it
passes vacuously here), and on Windows its parallel runs race on ``~/.semgrep/settings.yml``.
Instead the fixtures are copied to a temporary directory and scanned once.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

from shyena.config import rules_dir

FIXTURES = Path(__file__).parent / "rules" / "semgrep"
_ANNOTATION = re.compile(r"(shyena\.[\w.-]*\w)")
_KIND = re.compile(r"\b(ruleid|ok):")

pytestmark = [
    pytest.mark.real_tools,
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed"),
]


def expectations(root: Path) -> tuple[dict[tuple[str, str], set[int]], set[str]]:
    """``{(file, rule): {lines expected}}`` and the set of rules each file annotates."""
    expected: dict[tuple[str, str], set[int]] = defaultdict(set)
    annotated: set[tuple[str, str]] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        is_annotation = [bool(_ANNOTATION.search(l) and _KIND.search(l)) for l in lines]
        for i, line in enumerate(lines):
            if not is_annotation[i]:
                continue
            # Annotations may be stacked; each applies to the next non-annotation line.
            target = i + 1
            while target < len(lines) and is_annotation[target]:
                target += 1
            kind = _KIND.search(line).group(1)
            for rule in _ANNOTATION.findall(line):
                annotated.add((rel, rule))
                if kind == "ruleid":
                    expected[(rel, rule)].add(target + 1)
    return expected, annotated


@pytest.mark.parametrize("language", sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()))
def test_rule_fixtures(language: str, tmp_path: Path):
    target = tmp_path / language
    shutil.copytree(FIXTURES / language, target)
    proc = subprocess.run(
        ["semgrep", "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check",
         "--config", str(rules_dir() / language), str(target)],
        capture_output=True, text=True, encoding="utf-8", timeout=600,
    )
    assert proc.stdout, proc.stderr[-2000:]
    out = json.loads(proc.stdout)
    assert not out.get("errors"), out["errors"]

    expected, annotated = expectations(target)
    actual: dict[tuple[str, str], set[int]] = defaultdict(set)
    for r in out["results"]:
        rel = Path(r["path"]).resolve().relative_to(target.resolve()).as_posix()
        rule = r["check_id"][r["check_id"].rfind("shyena.") :]
        actual[(rel, rule)].add(r["start"]["line"])

    problems = []
    for key in sorted(annotated | set(actual)):
        if key not in annotated:
            problems.append(f"{key[0]}: {key[1]} fired on lines {sorted(actual[key])} with no annotation")
            continue
        missed = expected.get(key, set()) - actual.get(key, set())
        extra = actual.get(key, set()) - expected.get(key, set())
        if missed:
            problems.append(f"{key[0]}: {key[1]} missed lines {sorted(missed)}")
        if extra:
            problems.append(f"{key[0]}: {key[1]} wrongly fired on lines {sorted(extra)}")
    assert not problems, "\n".join(problems)

    # Every rule in the language's rule set has at least one positive fixture.
    rule_ids = set()
    for yml in (rules_dir() / language).glob("*.yml"):
        rule_ids |= set(re.findall(r"^\s*- id:\s*(\S+)", yml.read_text(encoding="utf-8"), re.MULTILINE))
    covered = {rule for (_, rule), lines in expected.items() if lines}
    assert rule_ids <= covered, f"rules without a positive fixture: {sorted(rule_ids - covered)}"
