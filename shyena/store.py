"""Persistence for scans and reviewer decisions.

Each scan shares its directory with the GRC core's test instance::

    runs/<id>/
      instance.json    the GRC TestInstance (core's view: probe results + findings)
      scan.json        the ScanRun (code view: lifecycle, components, metrics, gate)
      results.sarif    the SARIF bundle, one run per engine
      summary.json     what a CI step or PR decoration needs
      report.md        human-readable summary
      raw/             per-engine native output

Reviewer decisions live outside any run, keyed by fingerprint, one file per project::

    <home>/shyena/states/<project-key>.json
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vapt.core import instance as core_store

from shyena.config import runs_dir, states_dir
from shyena.models import ScanRun


# ------------------------------------------------------------------------------ runs


def scan_dir(scan_id: str) -> Path:
    return core_store.instance_dir(scan_id)


def workdir_for(scan_id: str) -> Path:
    return core_store.workdir_for(scan_id)


def save_scan(run: ScanRun) -> Path:
    directory = scan_dir(run.id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "scan.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    tmp.replace(path)
    return path


def load_scan(scan_id: str) -> ScanRun:
    path = scan_dir(scan_id) / "scan.json"
    if not path.exists():
        raise FileNotFoundError(f"No Shyena scan with id {scan_id!r}")
    return ScanRun.from_dict(json.loads(path.read_text(encoding="utf-8")))


def list_scans() -> list[ScanRun]:
    scans: list[ScanRun] = []
    for directory in runs_dir().iterdir():
        meta = directory / "scan.json"
        if meta.exists():
            try:
                scans.append(ScanRun.from_dict(json.loads(meta.read_text("utf-8"))))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    scans.sort(key=lambda s: s.started_at or "", reverse=True)
    return scans


def resolve_id(prefix: str) -> str:
    matches = [s.id for s in list_scans() if s.id.startswith(prefix)]
    if not matches:
        raise FileNotFoundError(f"No Shyena scan matching {prefix!r}")
    if len(matches) > 1:
        raise ValueError(f"Ambiguous id {prefix!r}: matches {', '.join(matches)}")
    return matches[0]


def find_baseline(repo_root: Path, *, base_commit: str | None, branch: str | None, exclude_id: str | None = None) -> ScanRun | None:
    """The scan to diff against: the latest completed scan of the base commit, else the
    latest completed scan of the same repository (same branch when known)."""
    root = str(repo_root.resolve())
    candidates = [s for s in list_scans() if s.repo_root == root and s.status == "completed" and s.id != exclude_id]
    if base_commit:
        for s in candidates:
            if s.commit == base_commit:
                return s
    if branch:
        for s in candidates:
            if s.branch == branch:
                return s
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------- states


def project_key(repo_root: Path) -> str:
    return hashlib.sha1(str(repo_root.resolve()).lower().encode("utf-8")).hexdigest()[:16]


def _states_path(repo_root: Path) -> Path:
    return states_dir() / f"{project_key(repo_root)}.json"


def load_states(repo_root: Path) -> dict[str, dict[str, Any]]:
    path = _states_path(repo_root)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data.get("states", {}) if isinstance(data, dict) else {}


def set_state(repo_root: Path, fingerprint: str, status: str, reason: str, set_by: str = "") -> dict[str, Any]:
    """Record an accepted / false-positive decision (or clear it with status ``open``)."""
    path = _states_path(repo_root)
    states = load_states(repo_root)
    if status == "open":
        states.pop(fingerprint, None)
        entry = {"fingerprint": fingerprint, "status": "open"}
    else:
        entry = {
            "status": status,
            "reason": reason,
            "set_by": set_by,
            "set_at": datetime.now(timezone.utc).isoformat(),
        }
        states[fingerprint] = entry
    path.write_text(
        json.dumps({"project": str(repo_root.resolve()), "states": states}, indent=2),
        encoding="utf-8",
    )
    return entry
