"""Cyclomatic complexity: Lizard's CSV, mapped to metrics and to ``smell`` findings for
functions over the policy's per-function limit."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from shyena.models import Category, CodeFinding, Location, Severity
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext
from shyena.repo import IGNORED_DIRS, rel

# Lizard CSV columns: NLOC, CCN, token, PARAM, length, location, file, function, long_name, start, end


class LizardProbe(CodeProbe):
    name = "lizard"
    binary = "lizard"
    description = "Cyclomatic complexity and function length across 20+ languages"
    install_hint = "pip install lizard"
    category = Category.SMELL
    native_output = "CSV"

    def wanted(self, profile) -> bool:
        return profile.quality in ("full", "full_with_dup_complexity")

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        limit = float(ctx.policy.get("new_code", {}).get("complexity_max_per_function", 15))
        args = ["--csv"]
        if ctx.depth.whole_tree:
            for ignored in sorted(IGNORED_DIRS):
                args += ["-x", f"*/{ignored}/*"]
            args.append(str(ctx.repo.root))
        else:
            files = ctx.source_files_in_scope()
            if not files:
                return ProbeOutput(note="skipped: no changed source files in scope")
            args += [str(ctx.repo.root / f) for f in files]
        proc = self.exec(args, cwd=ctx.repo.root)
        (workdir / "lizard.csv").write_text(proc.stdout, encoding="utf-8")
        out = ProbeOutput()
        max_ccn = 0.0
        total_ccn = 0.0
        functions = 0
        nloc = 0
        for row in csv.reader(io.StringIO(proc.stdout)):
            if len(row) < 11:
                continue
            try:
                row_nloc, ccn = int(row[0]), int(row[1])
                start = int(row[9])
            except ValueError:
                continue
            functions += 1
            nloc += row_nloc
            total_ccn += ccn
            max_ccn = max(max_ccn, float(ccn))
            if ccn > limit:
                path = rel(ctx.repo.root, row[6])
                out.findings.append(
                    CodeFinding(
                        title=f"{row[7]} has cyclomatic complexity {ccn} (limit {int(limit)})",
                        severity=Severity.HIGH if ccn > 2 * limit else Severity.MEDIUM,
                        target=ctx.target,
                        probe=self.name,
                        description=f"{row[8]} — {row_nloc} lines, {ccn} decision paths.",
                        remediation="Split the function; each branch of the decision tree should be its own, testable unit.",
                        rule_id="lizard:complexity",
                        category=Category.SMELL,
                        locations=[Location(path=path, start_line=start, end_line=int(row[10]) if row[10].isdigit() else None, snippet=row[8])],
                        scan_pass=self.scan_pass,
                    )
                )
        out.metrics.update({"functions": float(functions), "nloc": float(nloc), "complexity_max": max_ccn, "complexity_avg": round(total_ccn / functions, 2) if functions else 0.0})
        return out
