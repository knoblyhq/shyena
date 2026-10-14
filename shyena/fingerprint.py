"""Stable finding fingerprints.

A finding keeps its identity across scans when the code moves or is reformatted, so
reviewer decisions and the new / recurring / fixed lifecycle survive. SHA-256 over:

1. rule id, with the engine prefix;
2. file path relative to the repository root;
3. the primary line with whitespace collapsed, plus the line before and after,
   also collapsed — line numbers are excluded;
4. dependency findings: package URL without version, plus vulnerability id;
5. licence findings: package URL without version, plus the detected SPDX expression;
6. secrets: rule id plus a hash of the secret value, never the value itself
   (the probe stores that hash in ``evidence``).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from shyena.models import Category, CodeFinding

_SEP = "\x1f"
_VERSION_SUFFIX = re.compile(r"@[^@/]+$")


def collapse(text: str) -> str:
    """Whitespace-insensitive form of a line."""
    return " ".join(text.split())


def purl_without_version(purl: str | None) -> str:
    if not purl:
        return ""
    return _VERSION_SUFFIX.sub("", purl)


def context_lines(root: Path | None, rel_path: str, line: int) -> str:
    """Collapsed ``before | line | after`` at ``line`` (1-based) of ``rel_path``."""
    if not root or line <= 0:
        return ""
    path = root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    idx = line - 1
    if idx >= len(lines):
        return ""
    window = [lines[i] for i in (idx - 1, idx, idx + 1) if 0 <= i < len(lines)]
    return " | ".join(collapse(x) for x in window)


def compute(f: CodeFinding) -> str:
    parts: list[str] = [f.rule_id or f.title]
    if f.category is Category.DEPENDENCY:
        parts += [purl_without_version(f.component), f.cve or f.title]
    elif f.category is Category.LICENCE:
        parts += [purl_without_version(f.component), f.licence or ""]
    elif f.category is Category.SECRET:
        parts += [f.evidence]
    else:
        loc = f.primary
        if loc is not None:
            parts += [loc.path, f.context or collapse(loc.snippet)]
        else:
            parts += [f.target, collapse(f.evidence or f.description)]
    return hashlib.sha256(_SEP.join(parts).encode("utf-8", "replace")).hexdigest()


def enrich(f: CodeFinding, root: Path | None) -> CodeFinding:
    """Fill ``context`` from the working tree and recompute the id. Idempotent."""
    loc = f.primary
    if loc is not None and not f.context and f.category not in (
        Category.DEPENDENCY,
        Category.LICENCE,
        Category.SECRET,
    ):
        f.context = context_lines(root, loc.path, loc.start_line)
    f.refingerprint()
    return f


def short(fingerprint: str) -> str:
    return fingerprint[:12]
