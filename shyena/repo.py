"""Repository inspection: commit, base, changed files, changed lines, languages,
manifests and ``git blame``. Everything degrades gracefully on a plain directory."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Directories never scanned or counted.
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "runs",
}

#: Extension -> language, for the inventory and for choosing per-language engines.
LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".scala": "scala",
    ".ex": "elixir",
    ".exs": "elixir",
    ".sh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".tf": "terraform",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".html": "html",
    ".css": "css",
}

#: Manifests and lockfiles we recognise (name -> ecosystem).
MANIFESTS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "setup.py": "pypi",
    "composer.json": "packagist",
    "composer.lock": "packagist",
    "go.mod": "golang",
    "go.sum": "golang",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "Gemfile": "gem",
    "Gemfile.lock": "gem",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "mix.exs": "hex",
    "Dockerfile": "docker",
    "docker-compose.yml": "docker",
    "docker-compose.yaml": "docker",
}

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class RepoInfo:
    root: Path
    is_git: bool = False
    commit: str | None = None
    branch: str | None = None
    base_commit: str | None = None
    changed_files: list[str] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    file_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "is_git": self.is_git,
            "commit": self.commit,
            "branch": self.branch,
            "base_commit": self.base_commit,
            "changed_files": list(self.changed_files),
            "languages": dict(self.languages),
            "manifests": list(self.manifests),
            "file_count": self.file_count,
        }


# ------------------------------------------------------------------------------- git


def git(root: Path, *args: str, timeout: int = 60) -> str | None:
    """Run ``git`` in ``root``; return stripped stdout, or None on any failure."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _lines(out: str | None) -> list[str]:
    return [line.strip() for line in (out or "").splitlines() if line.strip()]


def resolve_base(root: Path, base: str | None) -> str | None:
    """Resolve a base ref to the merge-base with HEAD (what a pull request diffs against)."""
    if not base:
        return None
    merge_base = git(root, "merge-base", base, "HEAD")
    return merge_base or git(root, "rev-parse", base)


def changed_files(root: Path, base_commit: str | None) -> list[str]:
    """Files changed since ``base_commit`` (committed + working tree), or just the
    uncommitted + untracked changes when there is no base."""
    files: set[str] = set()
    if base_commit:
        files.update(_lines(git(root, "diff", "--name-only", f"{base_commit}...HEAD")))
    files.update(_lines(git(root, "diff", "--name-only", "HEAD")))
    files.update(_lines(git(root, "ls-files", "--others", "--exclude-standard")))
    return sorted(p.replace("\\", "/") for p in files)


def changed_lines(root: Path, base_commit: str | None) -> dict[str, set[int]]:
    """``{path: {new-side line numbers}}`` for the diff against ``base_commit`` (or HEAD)."""
    args = ["diff", "-U0", "--no-color"]
    args.append(f"{base_commit}...HEAD" if base_commit else "HEAD")
    out = git(root, *args)
    result: dict[str, set[int]] = {}
    current: str | None = None
    for line in (out or "").splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            current = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            if current:
                result.setdefault(current, set())
        elif line.startswith("@@") and current:
            m = _HUNK.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                result[current].update(range(start, start + max(count, 1)))
    if base_commit:
        # Uncommitted edits on top of HEAD also count as this change's lines.
        for path, lines in changed_lines(root, None).items():
            result.setdefault(path, set()).update(lines)
    return result


def blame_commit(root: Path, rel_path: str, line: int) -> str | None:
    """Commit that introduced ``line`` of ``rel_path``."""
    if line <= 0:
        return None
    out = git(root, "blame", "-L", f"{line},{line}", "--porcelain", "--", rel_path)
    if not out:
        return None
    first = out.splitlines()[0].split()
    return first[0] if first and len(first[0]) >= 7 else None


# ------------------------------------------------------------------------- the tree


def iter_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]
        for name in filenames:
            found.append(Path(dirpath) / name)
    return found


def rel(root: Path, path: Path | str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def detect_languages(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in files:
        lang = LANGUAGES.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def detect_manifests(root: Path, files: list[Path]) -> list[str]:
    return sorted(rel(root, f) for f in files if f.name in MANIFESTS)


def inspect(path: str | Path, base: str | None = None) -> RepoInfo:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a directory")
    info = RepoInfo(root=root)
    info.is_git = git(root, "rev-parse", "--is-inside-work-tree") == "true"
    if info.is_git:
        info.commit = git(root, "rev-parse", "HEAD")
        branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
        info.branch = None if branch in (None, "HEAD") else branch
        info.base_commit = resolve_base(root, base)
        info.changed_files = changed_files(root, info.base_commit)
    files = iter_files(root)
    info.file_count = len(files)
    info.languages = detect_languages(files)
    info.manifests = detect_manifests(root, files)
    return info
