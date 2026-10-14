"""SARIF 2.1.0 in and out.

* ``findings_from_sarif`` turns any engine's SARIF log into ``CodeFinding`` objects.
  Engines that do not emit SARIF get a thin mapper in their probe instead.
* ``to_sarif`` writes the scan's bundle: one ``run`` per engine, our fingerprint and
  lifecycle status in each result's ``fingerprints`` / ``properties`` bags.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shyena.models import Category, CodeFinding, Confidence, Location, ProbeResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}
_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_CVE = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.IGNORECASE)


def severity_from(level: str | None, security_severity: Any = None) -> Severity:
    """SARIF level, or the CVSS-style ``security-severity`` property when present:
    9.0+ critical, 7.0–8.9 high, 4.0–6.9 medium, below 4.0 low."""
    if security_severity not in (None, ""):
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
    return _LEVEL_TO_SEVERITY.get((level or "warning").lower(), Severity.MEDIUM)


def confidence_from(props: dict[str, Any]) -> Confidence:
    raw = str(props.get("precision") or props.get("confidence") or "").lower()
    if raw in ("very-high", "high"):
        return Confidence.HIGH
    if raw == "low":
        return Confidence.LOW
    return Confidence.MEDIUM


def load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


# ------------------------------------------------------------------------------ read


def _relative_uri(uri: str, repo_root: Path | None) -> str:
    uri = uri.replace("\\", "/")
    if uri.startswith("file:///"):
        uri = uri[8:] if re.match(r"file:///[A-Za-z]:/", uri) else uri[7:]
    elif uri.startswith("file://"):
        uri = uri[7:]
    if repo_root is not None:
        try:
            return Path(uri).resolve().relative_to(repo_root.resolve()).as_posix()
        except (ValueError, OSError):
            pass
    return uri.lstrip("./") if uri.startswith("./") else uri


def _location(loc: dict[str, Any], repo_root: Path | None, label: str = "") -> Location | None:
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri")
    if not uri:
        return None
    region = phys.get("region") or {}
    snippet = ((region.get("snippet") or {}).get("text")) or ""
    message = (loc.get("message") or {}).get("text") or ""
    return Location(
        path=_relative_uri(uri, repo_root),
        start_line=int(region.get("startLine") or 0),
        end_line=region.get("endLine"),
        start_col=region.get("startColumn"),
        end_col=region.get("endColumn"),
        snippet=snippet,
        label=label or message,
    )


def _trace(result: dict[str, Any], repo_root: Path | None) -> list[Location]:
    flows = result.get("codeFlows") or []
    if not flows:
        return []
    thread_flows = flows[0].get("threadFlows") or []
    if not thread_flows:
        return []
    steps = thread_flows[0].get("locations") or []
    out: list[Location] = []
    for i, step in enumerate(steps):
        label = "source" if i == 0 else "sink" if i == len(steps) - 1 else "step"
        loc = _location(step.get("location") or {}, repo_root, label)
        if loc is not None:
            out.append(loc)
    return out


def _rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool = run.get("tool") or {}
    rules: dict[str, dict[str, Any]] = {}
    for component in [tool.get("driver") or {}, *(tool.get("extensions") or [])]:
        for rule in component.get("rules") or []:
            if rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def findings_from_sarif(
    doc: dict[str, Any],
    *,
    probe: str,
    category: Category,
    target: str,
    repo_root: Path | None = None,
    engine: str | None = None,
    categorise=None,
) -> list[CodeFinding]:
    """Map every result in ``doc`` to a ``CodeFinding``.

    ``categorise(rule_id, rule, props) -> Category`` lets a probe route results from a
    mixed engine (Trivy) to the right dimension; otherwise ``category`` applies.
    """
    findings: list[CodeFinding] = []
    for run in doc.get("runs") or []:
        # Rule ids are namespaced by OUR probe name (``semgrep:…``), not the driver's
        # display name, so ids stay stable across engine versions and renames.
        prefix = (engine or probe).lower().replace(" ", "-")
        rules = _rules(run)
        for res in run.get("results") or []:
            if (res.get("kind") or "fail") not in ("fail", "review", "open"):
                continue
            raw_rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(raw_rule_id, {})
            # Re-reading our own bundle: the id already carries the prefix.
            if raw_rule_id.startswith(f"{prefix}:"):
                raw_rule_id = raw_rule_id[len(prefix) + 1 :]
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
            message = ((res.get("message") or {}).get("text") or "").strip()
            short = ((rule.get("shortDescription") or {}).get("text") or "").strip()
            title = short or (message.splitlines()[0][:140] if message else raw_rule_id)
            locations = [
                loc for loc in (_location(x, repo_root) for x in res.get("locations") or []) if loc
            ]
            tags = [str(t) for t in props.get("tags") or []]
            cwe = next((f"CWE-{m.group(1)}" for t in tags for m in [_CWE.search(t)] if m), None)
            cve_match = _CVE.search(raw_rule_id) or _CVE.search(message)
            help_uri = rule.get("helpUri")
            remediation = ((rule.get("help") or {}).get("text") or "").strip()
            cat = categorise(raw_rule_id, rule, props) if categorise else category
            findings.append(
                CodeFinding(
                    title=title,
                    severity=severity_from(level, props.get("security-severity")),
                    target=target,
                    probe=probe,
                    description=message,
                    evidence=locations[0].snippet if locations else "",
                    remediation=remediation[:2000],
                    references=[help_uri] if help_uri else [],
                    cwe=cwe,
                    cve=cve_match.group(1).upper() if cve_match else None,
                    rule_id=f"{prefix}:{raw_rule_id}",
                    category=cat,
                    locations=locations,
                    trace=_trace(res, repo_root),
                    confidence=confidence_from(props),
                    engine_raw=res,
                )
            )
    return findings


# ----------------------------------------------------------------------------- write


def _sarif_location(loc: Location) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(loc.start_line, 1)}
    if loc.end_line:
        region["endLine"] = loc.end_line
    if loc.start_col:
        region["startColumn"] = loc.start_col
    if loc.end_col:
        region["endColumn"] = loc.end_col
    if loc.snippet:
        region["snippet"] = {"text": loc.snippet}
    out: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": loc.path, "uriBaseId": "%SRCROOT%"},
            "region": region,
        }
    }
    if loc.label:
        out["message"] = {"text": loc.label}
    return out


def _sarif_result(f: CodeFinding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "level": _SEVERITY_TO_LEVEL[f.severity],
        "message": {"text": f.description or f.title},
        "fingerprints": {"shyena/v1": f.id},
        "properties": {
            "category": f.category.value,
            "severity": f.severity.value,
            "status": f.status.value,
            "confidence": f.confidence.value,
            "pass": f.scan_pass.value,
        },
    }
    if f.locations:
        result["locations"] = [_sarif_location(loc) for loc in f.locations]
    if f.trace:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {"locations": [{"location": _sarif_location(loc)} for loc in f.trace]}
                ]
            }
        ]
    props = result["properties"]
    for key in ("component", "licence", "cwe", "cve", "introduced_commit", "fix_available"):
        value = getattr(f, key)
        if value is not None and value != "":
            props[key] = value
    if f.triage:
        props["triage"] = f.triage.to_dict()
    return result


def to_sarif(results: list[ProbeResult], *, tool_version: str, scan_id: str) -> dict[str, Any]:
    """One run per engine. Findings that are not ``CodeFinding`` are written with the
    core's fields only."""
    runs: list[dict[str, Any]] = []
    for pr in results:
        rules_seen: dict[str, dict[str, Any]] = {}
        sarif_results = []
        for f in pr.findings:
            if not isinstance(f, CodeFinding):
                f = CodeFinding.from_dict({**f.to_dict(), "probe": pr.probe})
            sarif_results.append(_sarif_result(f))
            rules_seen.setdefault(
                f.rule_id,
                {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.title},
                    **({"helpUri": f.references[0]} if f.references else {}),
                    "properties": {**({"tags": [f.cwe]} if f.cwe else {})},
                },
            )
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": pr.probe,
                        "informationUri": "https://knobly.com/shyena",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "status": pr.status.value,
                    "duration_s": pr.duration_s,
                    **({"error": pr.error} if pr.error else {}),
                    **({"note": pr.note} if pr.note else {}),
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "properties": {"generator": f"shyena {tool_version}", "scan_id": scan_id},
        "runs": runs,
    }


def write(doc: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path
