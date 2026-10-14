"""Shared fixtures: an isolated state directory, no network, a throwaway git repo."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("VAPT_HOME", str(home))
    monkeypatch.delenv("VAPT_RUNS_DIR", raising=False)
    monkeypatch.setenv("SHYENA_OFFLINE", "1")
    return home


@pytest.fixture(autouse=True)
def no_external_tools(request, monkeypatch):
    """The suite must behave the same whether or not engines are installed on this
    machine: pretend none are. Tests marked ``real_tools`` opt out."""
    if "real_tools" in request.keywords:
        return
    from shyena.probes.base import CodeProbe

    monkeypatch.setattr(CodeProbe, "is_available", lambda self: bool(self.pure_python))


def pytest_configure(config):
    config.addinivalue_line("markers", "real_tools: runs the installed engine binaries for real")


def git(root: Path, *args: str) -> str:
    import os

    proc = subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True, check=True, env={**os.environ, **GIT_ENV})
    return proc.stdout.strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def git_repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("import os\n\ndef run(cmd):\n    return os.system(cmd)\n\nVERSION = 1\n", encoding="utf-8")
    (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (root / ".python-version").write_text("3.12\n", encoding="utf-8")
    commit_all(root, "initial")
    return root
