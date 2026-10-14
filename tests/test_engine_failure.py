"""A crash mid-scan must leave a failed record, never a scan stuck in ``running``."""

from __future__ import annotations

import pytest
from vapt.core import instance as core_store
from vapt.core.models import InstanceStatus

from shyena import engine, store


def test_crash_marks_scan_failed(git_repo, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("licence engine exploded")

    monkeypatch.setattr(engine.policy_mod, "licence_findings", boom)
    with pytest.raises(RuntimeError):
        engine.scan(git_repo)
    (run,) = store.list_scans()
    assert run.status == "failed"
    assert "exploded" in run.inventory["error"]
    assert core_store.load(run.id).status is InstanceStatus.FAILED


def test_failing_progress_hook_does_not_abort_the_scan(git_repo):
    def bad_hook(event, payload):
        raise UnicodeEncodeError("charmap", "→", 0, 1, "character maps to <undefined>")

    run = engine.scan(git_repo, on_event=bad_hook)
    assert run.status == "completed"
