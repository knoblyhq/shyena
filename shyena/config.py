"""Runtime configuration.

Shyena shares its state directory with the GRC core so ``vapt list``, ``vapt report``
and the GRC dashboard see Shyena scans. ``SHYENA_HOME`` (if set) becomes ``VAPT_HOME``;
otherwise the GRC core's own resolution applies (``VAPT_HOME``, then the working dir).

* ``SHYENA_HOME``     base directory for all state (runs/, finding states)
* ``SHYENA_OFFLINE``  set to ``1`` to skip every network lookup (end-of-life data etc.)
* ``VAPT_<TOOL>_PATH`` / ``tools.json``  external binary locations, as in the GRC core
"""

from __future__ import annotations

import os
from pathlib import Path

_home_override = os.environ.get("SHYENA_HOME")
if _home_override and not os.environ.get("VAPT_HOME"):
    os.environ["VAPT_HOME"] = _home_override

from vapt.config import DEFAULT_PROBE_TIMEOUT, home_dir, runs_dir  # noqa: E402  (after env setup)

__all__ = ["DEFAULT_PROBE_TIMEOUT", "home_dir", "runs_dir", "states_dir", "offline", "rules_dir"]

#: Default per-probe timeout, seconds. Deep-pass engines override this.
PROBE_TIMEOUT = DEFAULT_PROBE_TIMEOUT * 5

#: HTTP timeout for open-data lookups (endoflife.date, deps.dev), seconds.
HTTP_TIMEOUT = 8


def states_dir() -> Path:
    """Where reviewer decisions (accepted / false positive) live, one file per project."""
    path = home_dir() / "shyena" / "states"
    path.mkdir(parents=True, exist_ok=True)
    return path


def offline() -> bool:
    return os.environ.get("SHYENA_OFFLINE", "").strip() in ("1", "true", "yes")


def rules_dir() -> Path:
    """The packaged Semgrep rule set (our own rules, not the Semgrep registry)."""
    return Path(__file__).parent / "rules" / "semgrep"
