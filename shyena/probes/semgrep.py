"""Code vulnerabilities, pattern and intra-file taint: the Semgrep engine with our own
rule set (``shyena/rules/semgrep``), never the Semgrep registry. Rules tagged
``smell`` or ``deprecated`` are routed to those dimensions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shyena.config import rules_dir
from shyena.models import Category, CodeFinding
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext
from shyena.repo import IGNORED_DIRS


def categorise(rule_id: str, rule: dict[str, Any], props: dict[str, Any]) -> Category:
    tags = {str(t).lower() for t in props.get("tags") or []}
    if tags & {"smell", "maintainability", "style", "quality"}:
        return Category.SMELL
    if tags & {"deprecated", "compatibility", "deprecation"}:
        return Category.COMPATIBILITY
    return Category.VULNERABILITY


class SemgrepProbe(CodeProbe):
    name = "semgrep"
    binary = "semgrep"
    description = "Pattern and intra-file taint rules (our rule set) across 30+ languages"
    install_hint = "pip install semgrep  (or https://semgrep.dev/docs/getting-started/)"
    category = Category.VULNERABILITY

    def rule_paths(self, ctx: ScanContext) -> list[str]:
        configured = (ctx.policy.get("rules") or {}).get("semgrep")
        paths = [str(p) for p in configured] if isinstance(configured, list) else []
        if not paths and rules_dir().is_dir():
            paths = [str(rules_dir())]
        return paths

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        rules = self.rule_paths(ctx)
        if not rules:
            return ProbeOutput(note="skipped: no rule set configured")
        out_path = workdir / "semgrep.sarif"
        # Semgrep exits 0 on findings unless --error is given, so a hit is not a failure.
        args = ["scan", "--sarif", "--output", str(out_path), "--metrics=off", "--quiet"]
        for r in rules:
            args += ["--config", r]
        if ctx.depth.whole_tree:
            for ignored in sorted(IGNORED_DIRS):
                args += ["--exclude", ignored]
            args.append(str(ctx.repo.root))
        else:
            files = ctx.source_files_in_scope()
            if not files:
                return ProbeOutput(note="skipped: no changed source files in scope")
            args += [str(ctx.repo.root / f) for f in files]
        proc = self.exec(args, cwd=ctx.repo.root)
        if not out_path.exists():
            raise RuntimeError(f"semgrep exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        findings = [tidy(f) for f in self.findings_from_sarif_file(out_path, ctx, categorise=categorise)]
        return ProbeOutput(findings=findings, metrics={"sast_findings": float(len(findings))})


_FIRST_SENTENCE = re.compile(r"^(.*?[.!?])(\s|$)", re.DOTALL)


def tidy(f: CodeFinding) -> CodeFinding:
    """Semgrep prefixes rule ids with the config path (``D.shyena.shyena.rules…``) and
    titles every result "Semgrep Finding: <id>". Use our id and the rule's message."""
    raw = f.rule_id.split(":", 1)[-1]
    # The path prefix can itself contain "shyena." (D.shyena.shyena.rules.semgrep.php.…);
    # the real id is the last "shyena." onwards.
    if "shyena." in raw:
        raw = raw[raw.rfind("shyena.") :]
    f.rule_id = f"semgrep:{raw}"
    if f.title.lower().startswith("semgrep finding") or f.title == raw:
        text = " ".join(f.description.split())
        m = _FIRST_SENTENCE.match(text)
        f.title = (m.group(1) if m else text)[:140] or raw.rsplit(".", 1)[-1]
    return f
