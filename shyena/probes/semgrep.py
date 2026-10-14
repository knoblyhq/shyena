"""Code vulnerabilities, pattern and intra-file taint: the Semgrep engine with our own
rule set (``shyena/rules/semgrep``), never the Semgrep registry. Rules tagged
``smell`` or ``deprecated`` are routed to those dimensions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shyena.config import rules_dir
from shyena.models import Category
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext


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
            args.append(str(ctx.repo.root))
        else:
            files = ctx.source_files_in_scope()
            if not files:
                return ProbeOutput(note="skipped: no changed source files in scope")
            args += [str(ctx.repo.root / f) for f in files]
        proc = self.exec(args, cwd=ctx.repo.root)
        if not out_path.exists():
            raise RuntimeError(f"semgrep exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        findings = self.findings_from_sarif_file(out_path, ctx, categorise=categorise)
        return ProbeOutput(findings=findings, metrics={"sast_findings": float(len(findings))})
