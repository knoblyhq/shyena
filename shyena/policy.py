"""Policy: load ``.shyena.yml``, categorise licences, evaluate the gate.

Evaluation is deterministic: hard denies and thresholds fail the gate; warns never do.
The AI layer can demote a finding before the gate runs but can never turn a pass into
a fail (``triage.ai_can_block: false``).
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from shyena.models import Category, CodeFinding, Component, FindingStatus, GateResult, Location, Severity

POLICY_FILENAME = ".shyena.yml"

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "name": "default",
    "new_code": {
        "vulnerabilities": {"critical": 0, "high": 0},
        "secrets": 0,
        "dependency_vulns": {"critical": 0, "high_with_fix": 0},
        "smells": {"blocker": 0},
        "coverage_min_percent": 80,
        "duplication_max_percent": 3,
        "complexity_max_per_function": 15,
    },
    "licences": {
        # "unknown" = a licence text we could not classify; "undeclared" = no licence
        # metadata at all (common for requirements.txt scans), a warning by default.
        "production": {"deny": ["strong_copyleft", "network_copyleft", "unknown"], "warn": ["weak_copyleft", "undeclared"]},
        "development": {"deny": ["network_copyleft"], "warn": []},
        "exceptions": [],
    },
    "compatibility": {
        "fail_on_eol_runtime": True,
        "warn_on_eol_within_days": 180,
        "max_libyear_per_dependency": 3,
    },
    "triage": {
        "ai_threshold": "medium",
        "demote_on_ai_false_positive": True,
        "ai_can_block": False,
    },
    "deep_pass": {"block_on_taint_high": True},
    "depth": {
        "on_pull_request": "standard",
        "on_default_branch": "deep",
        "on_release_tag": "audit",
        "profiles": {},
    },
}

# ------------------------------------------------------------------------- licences

LICENCE_CATEGORY_ORDER = [
    "permissive",
    "weak_copyleft",
    "strong_copyleft",
    "network_copyleft",
    "proprietary",
    "unknown",  # a licence string we could not classify
    "undeclared",  # no licence metadata for the package at all
]

#: SPDX id (lower-cased, version suffixes like ``-only``/``-or-later`` stripped) -> category.
LICENCE_CATEGORIES: dict[str, str] = {
    "mit": "permissive",
    "mit-0": "permissive",
    "apache-2.0": "permissive",
    "bsd-2-clause": "permissive",
    "bsd-3-clause": "permissive",
    "bsd-4-clause": "permissive",
    "isc": "permissive",
    "0bsd": "permissive",
    "unlicense": "permissive",
    "cc0-1.0": "permissive",
    "zlib": "permissive",
    "psf-2.0": "permissive",
    "python-2.0": "permissive",
    "bsl-1.0": "permissive",
    "wtfpl": "permissive",
    "artistic-2.0": "permissive",
    "ofl-1.1": "permissive",
    "cc-by-4.0": "permissive",
    "mpl-2.0": "weak_copyleft",
    "mpl-1.1": "weak_copyleft",
    "lgpl-2.0": "weak_copyleft",
    "lgpl-2.1": "weak_copyleft",
    "lgpl-3.0": "weak_copyleft",
    "epl-1.0": "weak_copyleft",
    "epl-2.0": "weak_copyleft",
    "cddl-1.0": "weak_copyleft",
    "cddl-1.1": "weak_copyleft",
    "cc-by-sa-4.0": "weak_copyleft",
    "gpl-1.0": "strong_copyleft",
    "gpl-2.0": "strong_copyleft",
    "gpl-3.0": "strong_copyleft",
    "agpl-1.0": "network_copyleft",
    "agpl-3.0": "network_copyleft",
    "sspl-1.0": "network_copyleft",
    "busl-1.1": "proprietary",
    "elastic-2.0": "proprietary",
    "proprietary": "proprietary",
    "commercial": "proprietary",
}

_SPDX_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_SPDX_SUFFIX = re.compile(r"(-only|-or-later|\+)$", re.IGNORECASE)


def _licence_rank(token: str) -> int:
    key = _SPDX_SUFFIX.sub("", token.strip().lower())
    return LICENCE_CATEGORY_ORDER.index(LICENCE_CATEGORIES.get(key, "unknown"))


class _SpdxParser:
    """Tiny recursive-descent evaluator for SPDX expressions.

    expr := term ('OR' term)*      -> the most permissive branch (min rank)
    term := factor ('AND' factor)* -> the most restrictive part (max rank)
    factor := '(' expr ')' | ID ('WITH' ID)?
    """

    def __init__(self, expression: str) -> None:
        self.tokens = _SPDX_TOKEN.findall(expression)
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expr(self) -> int:
        rank = self.term()
        while self.peek() is not None and self.peek().upper() == "OR":
            self.take()
            rank = min(rank, self.term())
        return rank

    def term(self) -> int:
        rank = self.factor()
        while self.peek() is not None and self.peek().upper() == "AND":
            self.take()
            rank = max(rank, self.factor())
        return rank

    def factor(self) -> int:
        tok = self.peek()
        if tok is None:
            return LICENCE_CATEGORY_ORDER.index("unknown")
        if tok == "(":
            self.take()
            rank = self.expr()
            if self.peek() == ")":
                self.take()
            return rank
        self.take()
        if tok == ")":  # stray close paren
            return self.factor()
        rank = _licence_rank(tok)
        if self.peek() is not None and self.peek().upper() == "WITH":
            self.take()  # exception, e.g. "GPL-2.0-only WITH Classpath-exception-2.0"
            if self.peek() is not None:
                self.take()
        return rank


def categorise_licence(expression: str | None) -> str:
    """Category of an SPDX expression. ``A OR B`` takes the most permissive branch,
    ``A AND B`` the most restrictive; anything unrecognised is ``unknown``; no
    expression at all is ``undeclared``."""
    if not expression or not expression.strip():
        return "undeclared"
    parser = _SpdxParser(expression.strip())
    if not parser.tokens:
        return "unknown"
    return LICENCE_CATEGORY_ORDER[parser.expr()]


# ----------------------------------------------------------------------------- load


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def find_policy_file(repo_root: Path | None) -> Path | None:
    if repo_root is None:
        return None
    candidate = repo_root / POLICY_FILENAME
    return candidate if candidate.is_file() else None


def load(path: str | Path | None = None, repo_root: Path | None = None) -> dict[str, Any]:
    """The effective policy: defaults, overlaid with the file at ``path`` or the repo's
    ``.shyena.yml``. A missing file means the defaults."""
    policy_path = Path(path) if path else find_policy_file(repo_root)
    policy = copy.deepcopy(DEFAULT_POLICY)
    if policy_path is None:
        policy["_source"] = "defaults"
        return policy
    data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{policy_path}: policy must be a mapping")
    version = data.get("version", 1)
    if int(version) != 1:
        raise ValueError(f"{policy_path}: unsupported policy version {version!r} (expected 1)")
    policy = _merge(policy, data)
    policy["_source"] = str(policy_path)
    return policy


# ------------------------------------------------------------------- licence checks


@dataclass
class LicenceVerdict:
    component: Component
    category: str
    action: str  # deny | warn | allow | excepted
    reason: str = ""


def _exception_for(policy: dict[str, Any], purl: str, today: date) -> dict[str, Any] | None:
    from shyena.fingerprint import purl_without_version

    bare = purl_without_version(purl)
    for exc in policy.get("licences", {}).get("exceptions") or []:
        if not isinstance(exc, dict):
            continue
        if purl_without_version(str(exc.get("purl", ""))) != bare:
            continue
        expires = exc.get("expires")
        if expires:
            try:
                exp_date = expires if isinstance(expires, date) else date.fromisoformat(str(expires))
            except ValueError:
                exp_date = None
            if exp_date and exp_date < today:
                continue  # expired exceptions are ignored
        return exc
    return None


def licence_verdicts(policy: dict[str, Any], components: list[Component], today: date | None = None) -> list[LicenceVerdict]:
    today = today or date.today()
    out: list[LicenceVerdict] = []
    rules = policy.get("licences") or {}
    for comp in components:
        cat = categorise_licence(comp.licence)
        scope_rules = rules.get("development" if comp.dev else "production") or {}
        exc = _exception_for(policy, comp.purl, today)
        if exc is not None:
            out.append(LicenceVerdict(comp, cat, "excepted", str(exc.get("reason", ""))))
        elif cat in (scope_rules.get("deny") or []):
            out.append(LicenceVerdict(comp, cat, "deny"))
        elif cat in (scope_rules.get("warn") or []):
            out.append(LicenceVerdict(comp, cat, "warn"))
        else:
            out.append(LicenceVerdict(comp, cat, "allow"))
    return out


def licence_findings(policy: dict[str, Any], components: list[Component], target: str, today: date | None = None) -> list[CodeFinding]:
    """Our policy engine over the SBOM: one finding per denied or warned package."""
    findings: list[CodeFinding] = []
    for v in licence_verdicts(policy, components, today):
        if v.action not in ("deny", "warn"):
            continue
        comp = v.component
        scope = "development" if comp.dev else "production"
        if v.category == "undeclared":
            title = f"{comp.name}@{comp.version or '?'} has no licence metadata (undeclared)"
            description = (
                f"The SBOM carries no licence for this package, so it is on the {scope} {v.action} list as 'undeclared'. "
                "Manifest-only scans (requirements.txt without installed packages) often lack licence data; "
                "scan with the packages installed, or add a lockfile, to resolve it."
            )
            remediation = "Install the dependencies before scanning, or record the licence in a dated exception in .shyena.yml."
        else:
            title = f"{comp.name}@{comp.version or '?'} is {comp.licence or 'unlicensed'} ({v.category})"
            description = (
                f"Licence category '{v.category}' is on the {scope} {v.action} list. "
                f"Declared: {comp.licence_declared or '-'}; detected: {comp.licence_detected or '-'}."
            )
            remediation = "Replace the package, move it to development-only use, or add a dated exception to .shyena.yml with a reason."
        findings.append(
            CodeFinding(
                title=title,
                severity=Severity.HIGH if v.action == "deny" else Severity.LOW,
                target=target,
                probe="licence-policy",
                description=description,
                remediation=remediation,
                rule_id=f"shyena:licence.{v.action}",
                category=Category.LICENCE,
                component=comp.purl,
                licence=comp.licence,
                locations=[Location(path=comp.path)] if comp.path else [],
            )
        )
    return findings


# ----------------------------------------------------------------------------- gate

_SEVERITY_AT_LEAST = {
    "critical": (Severity.CRITICAL,),
    "high": (Severity.CRITICAL, Severity.HIGH),
    "medium": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM),
    "low": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW),
}


def severity_at_least(name: str) -> tuple[Severity, ...]:
    return _SEVERITY_AT_LEAST.get(str(name).lower(), _SEVERITY_AT_LEAST["medium"])


def _count(findings: list[CodeFinding], category: Category, severities: tuple[Severity, ...]) -> int:
    return sum(1 for f in findings if f.category is category and f.severity in severities)


def evaluate(
    policy: dict[str, Any],
    gate_findings: list[CodeFinding],
    metrics: dict[str, float] | None = None,
    components: list[Component] | None = None,
    today: date | None = None,
) -> GateResult:
    """Apply the policy to the findings that count (new, on changed lines, not
    accepted / false positive) and the scan's metrics. Returns pass/fail with reasons."""
    metrics = metrics or {}
    components = components or []
    counted = [f for f in gate_findings if f.status is FindingStatus.NEW]
    if policy.get("triage", {}).get("demote_on_ai_false_positive", True):
        counted = [f for f in counted if not (f.triage and f.triage.verdict == "false_positive")]
    nc = policy.get("new_code") or {}
    reasons: list[str] = []
    warnings: list[str] = []
    counts: dict[str, int] = {}

    def check(label: str, actual: int, limit: Any) -> None:
        counts[label] = actual
        if limit is None:
            return
        if actual > int(limit):
            reasons.append(f"{label}: {actual} > {limit}")

    vulns = nc.get("vulnerabilities") or {}
    for sev in ("critical", "high", "medium", "low"):
        if sev in vulns:
            check(f"new vulnerabilities {sev}", _count(counted, Category.VULNERABILITY, (Severity(sev),)), vulns[sev])

    check("new secrets", sum(1 for f in counted if f.category is Category.SECRET), nc.get("secrets"))

    dep = nc.get("dependency_vulns") or {}
    if "critical" in dep:
        check("new dependency vulns critical", _count(counted, Category.DEPENDENCY, (Severity.CRITICAL,)), dep["critical"])
    if "high_with_fix" in dep:
        n = sum(1 for f in counted if f.category is Category.DEPENDENCY and f.severity is Severity.HIGH and f.fix_available)
        check("new dependency vulns high (fix available)", n, dep["high_with_fix"])
    if "high" in dep:
        check("new dependency vulns high", _count(counted, Category.DEPENDENCY, (Severity.HIGH,)), dep["high"])

    smells = nc.get("smells") or {}
    if "blocker" in smells:
        check("new blocker smells", _count(counted, Category.SMELL, (Severity.CRITICAL, Severity.HIGH)), smells["blocker"])

    if "coverage_percent" in metrics and nc.get("coverage_min_percent") is not None:
        counts["coverage_percent"] = int(metrics["coverage_percent"])
        if metrics["coverage_percent"] < float(nc["coverage_min_percent"]):
            reasons.append(f"coverage {metrics['coverage_percent']:.1f}% < {nc['coverage_min_percent']}%")
    if "duplication_percent" in metrics and nc.get("duplication_max_percent") is not None:
        counts["duplication_percent"] = int(metrics["duplication_percent"])
        if metrics["duplication_percent"] > float(nc["duplication_max_percent"]):
            reasons.append(f"duplication {metrics['duplication_percent']:.1f}% > {nc['duplication_max_percent']}%")
    if "complexity_max" in metrics and nc.get("complexity_max_per_function") is not None:
        counts["complexity_max"] = int(metrics["complexity_max"])
        if metrics["complexity_max"] > float(nc["complexity_max_per_function"]):
            reasons.append(f"complexity {metrics['complexity_max']:.0f} > {nc['complexity_max_per_function']} per function")

    # Licences: hard denies fail, warns do not.
    denied = [f for f in counted if f.category is Category.LICENCE and f.rule_id.endswith(".deny")]
    warned = [f for f in gate_findings if f.category is Category.LICENCE and f.rule_id.endswith(".warn")]
    counts["licence denies"] = len(denied)
    for f in denied:
        reasons.append(f"licence denied: {f.title}")
    for f in warned:
        warnings.append(f"licence: {f.title}")

    # Compatibility.
    compat = policy.get("compatibility") or {}
    eol_runtime = [f for f in counted if f.category is Category.COMPATIBILITY and f.rule_id.endswith("eol.runtime")]
    eol_soon = [f for f in gate_findings if f.category is Category.COMPATIBILITY and f.rule_id.endswith("eol.soon")]
    counts["eol runtimes"] = len(eol_runtime)
    if compat.get("fail_on_eol_runtime") and eol_runtime:
        for f in eol_runtime:
            reasons.append(f"end-of-life runtime: {f.title}")
    for f in eol_soon:
        warnings.append(f"end-of-life soon: {f.title}")
    max_libyear = compat.get("max_libyear_per_dependency")
    if max_libyear is not None and "libyear_max" in metrics and metrics["libyear_max"] > float(max_libyear):
        warnings.append(f"stalest dependency is {metrics['libyear_max']:.1f} libyears behind (> {max_libyear})")

    # Deep-pass taint findings attributed to this change.
    if policy.get("deep_pass", {}).get("block_on_taint_high", True):
        taint_high = [
            f for f in counted
            if f.trace and f.scan_pass.value == "deep" and f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        counts["deep taint high"] = len(taint_high)
        for f in taint_high:
            reasons.append(f"deep-pass taint finding: {f.title}")

    return GateResult(passed=not reasons, reasons=reasons, warnings=warnings, counts=counts)
