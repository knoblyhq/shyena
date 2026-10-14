"""Dependency vulnerabilities: Grype over the SBOM. Uses Grype's JSON (its SARIF loses
the package URL and fix state), mapped thinly into dependency findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shyena.models import Category, CodeFinding, Location, Severity
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


def findings_from_grype_json(doc: dict[str, Any], *, probe: str, target: str) -> list[CodeFinding]:
    out: list[CodeFinding] = []
    for match in doc.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vuln.get("fix") or {}
        fixed_versions = [v for v in fix.get("versions") or [] if v]
        vuln_id = vuln.get("id", "unknown")
        purl = artifact.get("purl") or f"pkg:{artifact.get('type', 'generic')}/{artifact.get('name')}@{artifact.get('version')}"
        cvss = None
        for entry in vuln.get("cvss") or []:
            score = (entry.get("metrics") or {}).get("baseScore")
            if score is not None:
                cvss = max(cvss or 0, float(score))
        severity = _SEVERITY.get(str(vuln.get("severity", "unknown")).lower(), Severity.MEDIUM)
        locations = [Location(path=loc.get("path", "")) for loc in artifact.get("locations") or [] if loc.get("path")]
        out.append(
            CodeFinding(
                title=f"{vuln_id} in {artifact.get('name')}@{artifact.get('version')}",
                severity=severity,
                target=target,
                probe=probe,
                description=(vuln.get("description") or "").strip(),
                evidence=f"cvss={cvss}" if cvss is not None else "",
                remediation=f"Upgrade to {', '.join(fixed_versions)}." if fixed_versions else "No fixed version published yet.",
                references=[u for u in vuln.get("urls") or [] if u][:5] or ([vuln["dataSource"]] if vuln.get("dataSource") else []),
                cve=vuln_id if vuln_id.upper().startswith(("CVE-", "GHSA-")) else None,
                rule_id=f"grype:{vuln_id}",
                category=Category.DEPENDENCY,
                component=purl,
                locations=locations,
                fix_available=bool(fixed_versions),
                engine_raw={"vulnerability": {k: vuln.get(k) for k in ("id", "severity", "fix", "dataSource")}, "artifact": {"purl": purl}},
            )
        )
    return out


class GrypeProbe(CodeProbe):
    name = "grype"
    binary = "grype"
    description = "Known vulnerabilities in the SBOM's packages"
    install_hint = "https://github.com/anchore/grype#installation"
    category = Category.DEPENDENCY
    native_output = "JSON"

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        if ctx.sbom_path is None or not ctx.sbom_path.exists():
            return ProbeOutput(note="skipped: no SBOM from syft")
        out_path = workdir / "grype.json"
        # Depth dial `dependencies` (direct | transitive | transitive_reachable): Grype
        # matches the whole SBOM; direct-only filtering and reachability land with
        # lockfile parsing in Phase 2.
        args = [f"sbom:{ctx.sbom_path}", "-o", "json", "--file", str(out_path), "--quiet"]
        proc = self.exec(args, cwd=ctx.repo.root)
        if not out_path.exists():
            raise RuntimeError(f"grype exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        doc = json.loads(out_path.read_text(encoding="utf-8"))
        findings = findings_from_grype_json(doc, probe=self.name, target=ctx.target)
        for f in findings:
            f.scan_pass = self.scan_pass
        return ProbeOutput(findings=findings, metrics={"dependency_vulns": float(len(findings))})
