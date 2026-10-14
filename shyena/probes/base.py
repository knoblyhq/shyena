"""The analyser contract: a GRC ``Probe`` with the ``code`` scope and a ``repo`` target.

``CodeProbe.scan(ctx, workdir)`` is what a Shyena engine implements. It returns a
``ProbeOutput`` (findings, metrics, components, inventory facts). The GRC-core-facing
``run(target, workdir)`` adapts to that, so a code probe is also a valid core probe.

External engines inherit the core's ``ExternalTool`` and get its binary resolution
(``VAPT_<NAME>_PATH``, ``tools.json``, PATH) and clean skip when the binary is absent.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vapt.core.models import Scope, Target, TargetType
from vapt.probes.base import ExternalTool

from shyena import sarif
from shyena.config import PROBE_TIMEOUT
from shyena.depth import DepthProfile
from shyena.models import Category, CodeFinding, Component, Pass
from shyena.repo import LANGUAGES, RepoInfo, iter_files, rel


@dataclass
class ScanContext:
    repo: RepoInfo
    depth: DepthProfile
    policy: dict[str, Any]
    target: str
    sbom_path: Path | None = None
    components: list[Component] = field(default_factory=list)
    inventory: dict[str, Any] = field(default_factory=dict)

    def files_in_scope(self) -> list[str]:
        """Repository-relative paths this scan looks at, per the depth profile."""
        if self.depth.scope == "paths" and self.depth.paths:
            out: list[str] = []
            for p in self.depth.paths:
                full = self.repo.root / p
                if full.is_dir():
                    out.extend(rel(self.repo.root, f) for f in iter_files(full))
                elif full.is_file():
                    out.append(rel(self.repo.root, full))
            return sorted(set(out))
        if self.depth.scope in ("changed", "changed_plus_importers") and self.repo.is_git:
            existing = [p for p in self.repo.changed_files if (self.repo.root / p).is_file()]
            return existing
        return sorted(rel(self.repo.root, f) for f in iter_files(self.repo.root))

    def source_files_in_scope(self) -> list[str]:
        return [p for p in self.files_in_scope() if Path(p).suffix.lower() in LANGUAGES]


@dataclass
class ProbeOutput:
    findings: list[CodeFinding] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    components: list[Component] = field(default_factory=list)
    inventory: dict[str, Any] = field(default_factory=dict)
    note: str | None = None  # e.g. why nothing was done


class CodeProbe(ExternalTool):
    """Base for every Shyena engine adapter."""

    scopes = (Scope.CODE,)
    target_types = (TargetType.REPO,)
    #: Which dimension this engine serves (reports group by it).
    category: Category = Category.VULNERABILITY
    #: ``fast`` runs on every change; ``deep`` runs asynchronously on the whole tree.
    scan_pass: Pass = Pass.FAST
    #: True when the probe needs no external binary.
    pure_python: bool = False
    #: Native output format, for the tools table.
    native_output: str = "SARIF"
    timeout: int = PROBE_TIMEOUT

    #: Set by the engine before ``run``; lets the core's ``run(target, workdir)`` work.
    context: ScanContext | None = None

    # ---- contract ----------------------------------------------------------

    def is_available(self) -> bool:
        return True if self.pure_python else super().is_available()

    def wanted(self, profile: DepthProfile) -> bool:
        """Whether this profile asks for the probe at all (e.g. duplication only
        under ``full_with_dup_complexity`` quality)."""
        return True

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, target: Target, workdir) -> list[CodeFinding]:
        if self.context is None:
            raise RuntimeError(f"{self.name}: no scan context (use the Shyena engine)")
        return self.scan(self.context, Path(workdir)).findings

    # ---- helpers -----------------------------------------------------------

    def exec(self, args: list[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
        exe = self.resolve_binary()
        if exe is None:
            raise FileNotFoundError(f"{self.name}: executable not found")
        return subprocess.run(
            [exe, *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout or self.timeout,
            check=False,
        )

    def findings_from_sarif_file(self, path: Path, ctx: ScanContext, *, category: Category | None = None, categorise=None) -> list[CodeFinding]:
        if not path.exists():
            return []
        doc = sarif.load(path)
        out = sarif.findings_from_sarif(
            doc,
            probe=self.name,
            category=category or self.category,
            target=ctx.target,
            repo_root=ctx.repo.root,
            engine=self.name,
            categorise=categorise,
        )
        for f in out:
            f.scan_pass = self.scan_pass
        return out


class PythonCodeProbe(CodeProbe):
    """A probe implemented in Python with no external binary."""

    pure_python = True
    native_output = "findings"
