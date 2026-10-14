"""Depth configurator: four presets, ten dials.

A preset is a starting point. The policy's ``depth.profiles`` block overrides dials per
project (``extends`` chains presets), and ``--depth`` on the command line picks one.
Every scan records the resolved profile so a report says how hard it looked.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field, replace
from typing import Any

PRESET_NAMES = ("quick", "standard", "deep", "audit")
TRIGGERS = ("pull_request", "default_branch", "release_tag", "manual")


@dataclass
class DepthProfile:
    name: str
    #: changed | changed_plus_importers | tree | paths
    scope: str = "changed"
    paths: list[str] = field(default_factory=list)
    #: intra_file | cross_file_cached | cross_file | unbounded
    taint_mode: str = "intra_file"
    max_call_depth: int | None = None
    #: direct | transitive | transitive_reachable
    dependencies: str = "direct"
    #: declared | per_package | per_file
    licences: str = "declared"
    #: diff | since_base | last_n | full | full_all_branches
    secrets_history: str = "diff"
    secrets_last_n: int | None = None
    #: blockers | full | full_with_dup_complexity
    quality: str = "blockers"
    compatibility: bool = True
    eol_within_days: int = 180
    #: off | new_above | all_new | everything
    ai_triage: str = "off"
    ai_threshold: str = "medium"
    ai_provider: str = "null"
    ai_token_budget: int | None = None
    ai_summary: str | None = None
    branches: list[str] = field(default_factory=list)
    #: probe name -> reason it is switched off for this project
    disabled_probes: dict[str, str] = field(default_factory=dict)
    budget_minutes: float | None = None
    probe_budget_minutes: float | None = None
    passes: list[str] = field(default_factory=lambda: ["fast"])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def whole_tree(self) -> bool:
        return self.scope in ("tree", "paths")

    @property
    def runs_deep(self) -> bool:
        return "deep" in self.passes


PRESETS: dict[str, DepthProfile] = {
    "quick": DepthProfile(
        name="quick",
        scope="changed",
        taint_mode="intra_file",
        dependencies="direct",
        secrets_history="diff",
        quality="blockers",
        ai_triage="off",
        budget_minutes=1,
    ),
    "standard": DepthProfile(
        name="standard",
        scope="changed_plus_importers",
        taint_mode="cross_file_cached",
        max_call_depth=4,
        dependencies="transitive",
        licences="per_package",
        secrets_history="since_base",
        quality="full",
        ai_triage="new_above",
        ai_threshold="medium",
        budget_minutes=10,
    ),
    "deep": DepthProfile(
        name="deep",
        scope="tree",
        taint_mode="cross_file",
        max_call_depth=8,
        dependencies="transitive_reachable",
        licences="per_package",
        secrets_history="full",
        quality="full_with_dup_complexity",
        ai_triage="all_new",
        budget_minutes=120,
        passes=["fast", "deep"],
    ),
    "audit": DepthProfile(
        name="audit",
        scope="tree",
        taint_mode="unbounded",
        dependencies="transitive_reachable",
        licences="per_file",
        secrets_history="full_all_branches",
        quality="full_with_dup_complexity",
        ai_triage="everything",
        ai_summary="executive",
        budget_minutes=None,
        passes=["fast", "deep"],
    ),
}


def _apply(profile: DepthProfile, spec: dict[str, Any]) -> DepthProfile:
    """Overlay one ``depth.profiles.<name>`` block onto ``profile``."""
    p = replace(profile)
    if "scope" in spec:
        p.scope = str(spec["scope"])
    if "paths" in spec:
        p.paths = list(spec["paths"] or [])
    taint = spec.get("taint")
    if isinstance(taint, dict):
        p.taint_mode = str(taint.get("mode", p.taint_mode))
        if "max_call_depth" in taint:
            p.max_call_depth = taint["max_call_depth"]
    elif isinstance(taint, str):
        p.taint_mode = taint
    if "dependencies" in spec:
        p.dependencies = str(spec["dependencies"])
    if "licences" in spec:
        p.licences = str(spec["licences"])
    secrets = spec.get("secrets_history", spec.get("secrets"))
    if isinstance(secrets, dict):
        p.secrets_history = str(secrets.get("mode", p.secrets_history))
        p.secrets_last_n = secrets.get("last_n", p.secrets_last_n)
    elif secrets is not None:
        p.secrets_history = str(secrets)
    if "quality" in spec:
        p.quality = str(spec["quality"])
    compat = spec.get("compatibility")
    if isinstance(compat, dict):
        p.compatibility = bool(compat.get("enabled", p.compatibility))
        p.eol_within_days = int(compat.get("eol_within_days", p.eol_within_days))
    elif isinstance(compat, bool):
        p.compatibility = compat
    ai = spec.get("ai_triage")
    if isinstance(ai, dict):
        p.ai_triage = str(ai.get("when", p.ai_triage))
        p.ai_threshold = str(ai.get("threshold", p.ai_threshold))
        p.ai_provider = str(ai.get("provider", p.ai_provider))
        p.ai_token_budget = ai.get("budget_tokens", p.ai_token_budget)
        p.ai_summary = ai.get("summary", p.ai_summary)
    elif isinstance(ai, str):
        p.ai_triage = ai
    if "branches" in spec:
        p.branches = list(spec["branches"] or [])
    probes = spec.get("probes")
    if isinstance(probes, dict):
        disable = probes.get("disable") or {}
        if isinstance(disable, dict):
            p.disabled_probes = {**p.disabled_probes, **{str(k): str(v) for k, v in disable.items()}}
        elif isinstance(disable, list):
            p.disabled_probes = {**p.disabled_probes, **{str(k): "disabled in policy" for k in disable}}
    if "budget_minutes" in spec:
        p.budget_minutes = spec["budget_minutes"]
    if "probe_budget_minutes" in spec:
        p.probe_budget_minutes = spec["probe_budget_minutes"]
    if "passes" in spec:
        p.passes = list(spec["passes"])
    return p


def build(name: str, profiles: dict[str, Any] | None = None, _seen: tuple[str, ...] = ()) -> DepthProfile:
    """A preset plus the policy's overrides for it, following ``extends`` chains."""
    profiles = profiles or {}
    if name in _seen:
        raise ValueError(f"depth profile {name!r}: circular 'extends' chain {_seen + (name,)}")
    spec = profiles.get(name) or {}
    parent_name = spec.get("extends")
    if parent_name:
        base = build(str(parent_name), profiles, _seen + (name,))
    elif name in PRESETS:
        base = copy.deepcopy(PRESETS[name])
    else:
        raise ValueError(f"unknown depth profile {name!r}; presets are {', '.join(PRESET_NAMES)}")
    profile = _apply(base, spec)
    profile.name = name
    return profile


def resolve(depth_policy: dict[str, Any] | None, *, trigger: str = "pull_request", override: str | None = None) -> DepthProfile:
    """Which profile this scan runs: ``--depth`` wins, then ``depth.on_<trigger>``,
    then ``standard``."""
    depth_policy = depth_policy or {}
    name = override or depth_policy.get(f"on_{trigger}") or "standard"
    return build(str(name), depth_policy.get("profiles") or {})
