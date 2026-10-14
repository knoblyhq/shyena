"""Secrets: Gitleaks over the diff, the history since the base commit, or the full
history, per the depth profile. The secret value never leaves this module: evidence
is a SHA-256 of it, snippets and raw output are dropped."""

from __future__ import annotations

import hashlib
from pathlib import Path

from shyena.models import Category, CodeFinding
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext


def scrub(f: CodeFinding) -> CodeFinding:
    raw = f.engine_raw or {}
    secret = ""
    for loc in raw.get("locations") or []:
        snippet = (((loc.get("physicalLocation") or {}).get("region") or {}).get("snippet") or {}).get("text")
        if snippet:
            secret = snippet
            break
    if not secret:
        secret = f.evidence or f.description
    digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:24]
    f.evidence = f"sha256:{digest}"
    f.description = f"Possible secret matched rule {f.rule_id.split(':', 1)[-1]}. The value is withheld; its hash is the evidence."
    for loc in f.locations:
        loc.snippet = ""
    f.engine_raw = None
    f.refingerprint()
    return f


class GitleaksProbe(CodeProbe):
    name = "gitleaks"
    binary = "gitleaks"
    description = "Hard-coded secrets in the change, since the base commit, or across history"
    install_hint = "https://github.com/gitleaks/gitleaks#installing"
    category = Category.SECRET

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        out_path = workdir / "gitleaks.sarif"
        args = ["detect", "--source", str(ctx.repo.root), "--report-format", "sarif", "--report-path", str(out_path), "--exit-code", "0", "--no-banner"]
        mode = ctx.depth.secrets_history
        if not ctx.repo.is_git or mode == "diff":
            args.append("--no-git")
        elif mode == "since_base" and ctx.repo.base_commit:
            args += ["--log-opts", f"{ctx.repo.base_commit}..HEAD"]
        elif mode == "last_n" and ctx.depth.secrets_last_n:
            args += ["--log-opts", f"-n {ctx.depth.secrets_last_n}"]
        elif mode == "full_all_branches":
            args += ["--log-opts", "--all"]
        proc = self.exec(args, cwd=ctx.repo.root)
        if not out_path.exists():
            raise RuntimeError(f"gitleaks exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        findings = [scrub(f) for f in self.findings_from_sarif_file(out_path, ctx)]
        try:
            out_path.unlink()  # the native report holds the secret values
        except OSError:
            pass
        return ProbeOutput(findings=findings, metrics={"secrets": float(len(findings))})
