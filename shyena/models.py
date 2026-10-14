"""Shyena's domain model: the GRC core's ``Finding`` with the fields code analysis needs.

Nothing is removed from the core model; ``CodeFinding`` adds rule, category, locations,
dataflow trace, component, licence, confidence, lifecycle status, AI triage and the
introducing commit. Every model round-trips through ``to_dict`` / ``from_dict``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from vapt.core.models import Finding, ProbeResult, ProbeStatus, Severity

__all__ = [
    "Severity",
    "ProbeResult",
    "ProbeStatus",
    "Category",
    "Confidence",
    "FindingStatus",
    "Pass",
    "Location",
    "Triage",
    "CodeFinding",
    "Component",
    "GateResult",
    "ScanRun",
]


# --------------------------------------------------------------------------- enums


class Category(str, Enum):
    VULNERABILITY = "vulnerability"
    DEPENDENCY = "dependency"
    LICENCE = "licence"
    SECRET = "secret"
    SMELL = "smell"
    COMPATIBILITY = "compatibility"

    def __str__(self) -> str:
        return self.value


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    NEW = "new"
    RECURRING = "recurring"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class Pass(str, Enum):
    FAST = "fast"
    DEEP = "deep"


# ------------------------------------------------------------------------ locations


@dataclass
class Location:
    """A place in the tree. ``label`` is used on trace steps (source / step / sink)."""

    path: str
    start_line: int = 0
    end_line: int | None = None
    start_col: int | None = None
    end_col: int | None = None
    snippet: str = ""
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_col": self.start_col,
            "end_col": self.end_col,
            "snippet": self.snippet,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Location":
        return cls(
            path=d["path"],
            start_line=d.get("start_line", 0),
            end_line=d.get("end_line"),
            start_col=d.get("start_col"),
            end_col=d.get("end_col"),
            snippet=d.get("snippet", ""),
            label=d.get("label", ""),
        )


@dataclass
class Triage:
    """What the AI layer said about one finding. Append-only in the data model."""

    verdict: str  # true_positive | false_positive | uncertain
    confidence: float
    explanation: str = ""
    fix: str = ""
    model: str = ""
    prompt_version: str = ""
    tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "fix": self.fix,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "tokens": self.tokens,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Triage":
        return cls(
            verdict=d["verdict"],
            confidence=float(d.get("confidence", 0)),
            explanation=d.get("explanation", ""),
            fix=d.get("fix", ""),
            model=d.get("model", ""),
            prompt_version=d.get("prompt_version", ""),
            tokens=int(d.get("tokens", 0)),
        )


# -------------------------------------------------------------------------- finding


@dataclass
class CodeFinding(Finding):
    """A GRC ``Finding`` plus everything code analysis adds.

    ``id`` is the stable fingerprint (see :mod:`shyena.fingerprint`); it survives line
    shifts and reformatting, so reviewer decisions keyed by it carry across scans.

    For secrets, ``evidence`` must hold a hash of the secret value, never the value.
    """

    rule_id: str = ""
    category: Category = Category.VULNERABILITY
    locations: list[Location] = field(default_factory=list)
    trace: list[Location] = field(default_factory=list)
    component: str | None = None  # package URL from the SBOM
    licence: str | None = None  # SPDX expression
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    triage: Triage | None = None
    introduced_commit: str | None = None
    engine_raw: dict[str, Any] | None = None
    fix_available: bool | None = None  # dependency findings: a fixed version exists
    scan_pass: Pass = Pass.FAST
    context: str = ""  # collapsed line before / at / after the primary location

    def __post_init__(self) -> None:
        if isinstance(self.category, str):
            self.category = Category(self.category)
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)
        if isinstance(self.scan_pass, str):
            self.scan_pass = Pass(self.scan_pass)
        if not self.rule_id:
            self.rule_id = f"{self.probe}:{self.title}"
        super().__post_init__()

    # ---- identity ----------------------------------------------------------

    @property
    def primary(self) -> Location | None:
        return self.locations[0] if self.locations else None

    def fingerprint(self) -> str:
        from shyena.fingerprint import compute  # local import: fingerprint imports models

        return compute(self)

    def refingerprint(self) -> str:
        self.id = self.fingerprint()
        return self.id

    # ---- serialization -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "rule_id": self.rule_id,
                "category": self.category.value,
                "locations": [loc.to_dict() for loc in self.locations],
                "trace": [loc.to_dict() for loc in self.trace],
                "component": self.component,
                "licence": self.licence,
                "confidence": self.confidence.value,
                "status": self.status.value,
                "triage": self.triage.to_dict() if self.triage else None,
                "introduced_commit": self.introduced_commit,
                "engine_raw": self.engine_raw,
                "fix_available": self.fix_available,
                "scan_pass": self.scan_pass.value,
                "context": self.context,
            }
        )
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CodeFinding":
        return cls(
            title=d["title"],
            severity=Severity(d["severity"]),
            target=d["target"],
            probe=d["probe"],
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""),
            references=list(d.get("references", [])),
            cwe=d.get("cwe"),
            cve=d.get("cve"),
            id=d.get("id", ""),
            rule_id=d.get("rule_id", ""),
            category=Category(d.get("category", "vulnerability")),
            locations=[Location.from_dict(x) for x in d.get("locations", [])],
            trace=[Location.from_dict(x) for x in d.get("trace", [])],
            component=d.get("component"),
            licence=d.get("licence"),
            confidence=Confidence(d.get("confidence", "medium")),
            status=FindingStatus(d.get("status", "new")),
            triage=Triage.from_dict(d["triage"]) if d.get("triage") else None,
            introduced_commit=d.get("introduced_commit"),
            engine_raw=d.get("engine_raw"),
            fix_available=d.get("fix_available"),
            scan_pass=Pass(d.get("scan_pass", "fast")),
            context=d.get("context", ""),
        )


# ------------------------------------------------------------------------ component


@dataclass
class Component:
    """One package from the SBOM."""

    purl: str
    name: str
    version: str = ""
    ecosystem: str = ""
    direct: bool | None = None
    dev: bool = False
    licence_declared: str | None = None
    licence_detected: str | None = None
    path: str = ""  # manifest or lockfile that pulled it in

    @property
    def licence(self) -> str | None:
        return self.licence_detected or self.licence_declared

    def to_dict(self) -> dict[str, Any]:
        return {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
            "dev": self.dev,
            "licence_declared": self.licence_declared,
            "licence_detected": self.licence_detected,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Component":
        return cls(
            purl=d["purl"],
            name=d.get("name", ""),
            version=d.get("version", ""),
            ecosystem=d.get("ecosystem", ""),
            direct=d.get("direct"),
            dev=bool(d.get("dev", False)),
            licence_declared=d.get("licence_declared"),
            licence_detected=d.get("licence_detected"),
            path=d.get("path", ""),
        )


# ----------------------------------------------------------------------------- gate


@dataclass
class GateResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)  # why it failed
    warnings: list[str] = field(default_factory=list)  # did not fail, worth a look
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "counts": dict(self.counts),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GateResult":
        return cls(
            passed=bool(d.get("passed")),
            reasons=list(d.get("reasons", [])),
            warnings=list(d.get("warnings", [])),
            counts=dict(d.get("counts", {})),
        )


# ------------------------------------------------------------------------------ scan


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanRun:
    """One Shyena scan. The GRC ``TestInstance`` under the same id holds the probe
    results in the core's shape; ``scan.json`` (this) holds the code-specific view."""

    id: str
    name: str
    repo_root: str
    commit: str | None = None
    base_commit: str | None = None
    branch: str | None = None
    changed_files: list[str] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    depth: str = "standard"
    depth_profile: dict[str, Any] = field(default_factory=dict)
    policy_name: str = "default"
    trigger: str = "pull_request"
    scan_pass: str = "fast"
    status: str = "created"
    started_at: str | None = None
    finished_at: str | None = None
    baseline_id: str | None = None
    probe_runs: list[dict[str, Any]] = field(default_factory=list)
    findings: list[CodeFinding] = field(default_factory=list)
    fixed: list[CodeFinding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    inventory: dict[str, Any] = field(default_factory=dict)
    gate: GateResult | None = None

    # ---- views -------------------------------------------------------------

    def by_status(self, status: FindingStatus) -> list[CodeFinding]:
        return [f for f in self.findings if f.status is status]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def category_counts(self) -> dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for f in self.findings:
            counts[f.category.value] += 1
        return counts

    # ---- serialization -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "repo_root": self.repo_root,
            "commit": self.commit,
            "base_commit": self.base_commit,
            "branch": self.branch,
            "changed_files": list(self.changed_files),
            "languages": dict(self.languages),
            "manifests": list(self.manifests),
            "depth": self.depth,
            "depth_profile": self.depth_profile,
            "policy_name": self.policy_name,
            "trigger": self.trigger,
            "scan_pass": self.scan_pass,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "baseline_id": self.baseline_id,
            "probe_runs": list(self.probe_runs),
            "findings": [f.to_dict() for f in self.findings],
            "fixed": [f.to_dict() for f in self.fixed],
            "components": [c.to_dict() for c in self.components],
            "metrics": dict(self.metrics),
            "inventory": self.inventory,
            "gate": self.gate.to_dict() if self.gate else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanRun":
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            repo_root=d.get("repo_root", ""),
            commit=d.get("commit"),
            base_commit=d.get("base_commit"),
            branch=d.get("branch"),
            changed_files=list(d.get("changed_files", [])),
            languages=dict(d.get("languages", {})),
            manifests=list(d.get("manifests", [])),
            depth=d.get("depth", "standard"),
            depth_profile=d.get("depth_profile", {}),
            policy_name=d.get("policy_name", "default"),
            trigger=d.get("trigger", "pull_request"),
            scan_pass=d.get("scan_pass", "fast"),
            status=d.get("status", "created"),
            started_at=d.get("started_at"),
            finished_at=d.get("finished_at"),
            baseline_id=d.get("baseline_id"),
            probe_runs=list(d.get("probe_runs", [])),
            findings=[CodeFinding.from_dict(x) for x in d.get("findings", [])],
            fixed=[CodeFinding.from_dict(x) for x in d.get("fixed", [])],
            components=[Component.from_dict(x) for x in d.get("components", [])],
            metrics=dict(d.get("metrics", {})),
            inventory=d.get("inventory", {}),
            gate=GateResult.from_dict(d["gate"]) if d.get("gate") else None,
        )

    def mark_started(self) -> None:
        self.status = "running"
        self.started_at = _now_iso()

    def mark_finished(self, status: str) -> None:
        self.status = status
        self.finished_at = _now_iso()
