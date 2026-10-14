"""Containers, infrastructure code and config: Trivy in filesystem mode, SARIF out.
Misconfiguration rules land in ``vulnerability``; CVE rules land in ``dependency``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shyena.models import Category
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext


def categorise(rule_id: str, rule: dict[str, Any], props: dict[str, Any]) -> Category:
    upper = rule_id.upper()
    if upper.startswith(("CVE-", "GHSA-")) or "vulnerability" in str(props.get("tags", "")).lower():
        return Category.DEPENDENCY
    return Category.VULNERABILITY


class TrivyProbe(CodeProbe):
    name = "trivy"
    binary = "trivy"
    description = "Dockerfiles, Terraform, Kubernetes and Helm misconfigurations; container package CVEs"
    install_hint = "https://trivy.dev/latest/getting-started/installation/"
    category = Category.VULNERABILITY

    def wanted(self, profile) -> bool:
        return True

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        out_path = workdir / "trivy.sarif"
        scanners = "misconfig" if ctx.sbom_path is not None else "misconfig,vuln"
        proc = self.exec(
            ["fs", "--scanners", scanners, "--format", "sarif", "--output", str(out_path), "--quiet", "--exit-code", "0", str(ctx.repo.root)],
            cwd=ctx.repo.root,
        )
        if not out_path.exists():
            raise RuntimeError(f"trivy exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        findings = self.findings_from_sarif_file(out_path, ctx, categorise=categorise)
        return ProbeOutput(findings=findings, metrics={"iac_findings": float(len(findings))})
