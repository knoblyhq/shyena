"""Finding lifecycle: new, recurring, fixed; reviewer decisions; gate eligibility.

Clean as you code: the gate sees only ``new`` findings whose primary line is in the
change (dependency, licence, secret and compatibility findings count regardless of
line, since they have no meaningful line in the diff).
"""

from __future__ import annotations

from typing import Any

from shyena.models import Category, CodeFinding, FindingStatus

_LINELESS = (Category.DEPENDENCY, Category.LICENCE, Category.SECRET, Category.COMPATIBILITY)


def classify(
    findings: list[CodeFinding],
    baseline: list[CodeFinding],
    states: dict[str, dict[str, Any]],
) -> tuple[list[CodeFinding], list[CodeFinding]]:
    """Set each finding's status against the baseline scan and reviewer states.
    Returns ``(current, fixed)``: ``fixed`` are baseline findings no longer present."""
    baseline_ids = {f.id for f in baseline}
    current_ids = {f.id for f in findings}
    for f in findings:
        decision = states.get(f.id)
        if decision and decision.get("status") in (FindingStatus.ACCEPTED.value, FindingStatus.FALSE_POSITIVE.value):
            f.status = FindingStatus(decision["status"])
        elif f.id in baseline_ids:
            f.status = FindingStatus.RECURRING
        else:
            f.status = FindingStatus.NEW
    fixed: list[CodeFinding] = []
    for f in baseline:
        if f.id not in current_ids and f.status is not FindingStatus.FIXED:
            fixed_finding = CodeFinding.from_dict(f.to_dict())
            fixed_finding.status = FindingStatus.FIXED
            fixed.append(fixed_finding)
    return findings, fixed


def gate_eligible(f: CodeFinding, changed_lines: dict[str, set[int]] | None) -> bool:
    """Does this finding count toward the gate?"""
    if f.status is not FindingStatus.NEW:
        return False
    if changed_lines is None or f.category in _LINELESS:
        return True
    loc = f.primary
    if loc is None:
        return False
    lines = changed_lines.get(loc.path)
    if not lines:
        return False
    start = loc.start_line or 0
    end = loc.end_line or start
    return any(n in lines for n in range(start, end + 1)) if start else False
