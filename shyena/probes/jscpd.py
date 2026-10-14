"""Duplication: jscpd's JSON report, mapped to a duplication metric and ``smell``
findings per duplicated block."""

from __future__ import annotations

import json
from pathlib import Path

from shyena.models import Category, CodeFinding, Location, Severity
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext
from shyena.repo import rel


class JscpdProbe(CodeProbe):
    name = "jscpd"
    binary = "jscpd"
    description = "Copy-paste detection across any language"
    install_hint = "npm install -g jscpd"
    category = Category.SMELL
    native_output = "JSON"

    def wanted(self, profile) -> bool:
        return profile.quality == "full_with_dup_complexity"

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        out_dir = workdir / "jscpd"
        out_dir.mkdir(parents=True, exist_ok=True)
        proc = self.exec(
            ["--reporters", "json", "--output", str(out_dir), "--silent", "--gitignore", "--ignore", "**/node_modules/**,**/.venv/**,**/runs/**", str(ctx.repo.root)],
            cwd=ctx.repo.root,
        )
        report = out_dir / "jscpd-report.json"
        if not report.exists():
            raise RuntimeError(f"jscpd exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        doc = json.loads(report.read_text(encoding="utf-8"))
        total = (doc.get("statistics") or {}).get("total") or {}
        out = ProbeOutput(metrics={"duplication_percent": float(total.get("percentage", 0.0)), "duplicated_lines": float(total.get("duplicatedLines", 0))})
        for dup in doc.get("duplicates") or []:
            first, second = dup.get("firstFile") or {}, dup.get("secondFile") or {}
            lines = int(dup.get("lines", 0))
            p1, p2 = rel(ctx.repo.root, first.get("name", "")), rel(ctx.repo.root, second.get("name", ""))
            out.findings.append(
                CodeFinding(
                    title=f"{lines} duplicated lines between {p1} and {p2}",
                    severity=Severity.LOW,
                    target=ctx.target,
                    probe=self.name,
                    description=f"{p1}:{first.get('startLoc', {}).get('line')} duplicates {p2}:{second.get('startLoc', {}).get('line')} ({dup.get('tokens', 0)} tokens).",
                    remediation="Extract the shared block into one function or module.",
                    rule_id="jscpd:duplicate",
                    category=Category.SMELL,
                    locations=[
                        Location(path=p1, start_line=int((first.get("startLoc") or {}).get("line", 0)), end_line=(first.get("endLoc") or {}).get("line"), label="first copy"),
                        Location(path=p2, start_line=int((second.get("startLoc") or {}).get("line", 0)), end_line=(second.get("endLoc") or {}).get("line"), label="second copy"),
                    ],
                    scan_pass=self.scan_pass,
                )
            )
        return out
