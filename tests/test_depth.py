import pytest

from shyena import depth


def test_presets_match_the_architecture_table():
    q, s, d, a = (depth.build(n) for n in depth.PRESET_NAMES)
    assert (q.scope, q.taint_mode, q.dependencies, q.secrets_history, q.ai_triage, q.budget_minutes) == ("changed", "intra_file", "direct", "diff", "off", 1)
    assert (s.scope, s.taint_mode, s.max_call_depth, s.dependencies, s.secrets_history, s.ai_triage, s.budget_minutes) == ("changed_plus_importers", "cross_file_cached", 4, "transitive", "since_base", "new_above", 10)
    assert (d.scope, d.taint_mode, d.max_call_depth, d.dependencies, d.secrets_history, d.ai_triage, d.budget_minutes) == ("tree", "cross_file", 8, "transitive_reachable", "full", "all_new", 120)
    assert (a.scope, a.taint_mode, a.licences, a.secrets_history, a.ai_triage, a.ai_summary, a.budget_minutes) == ("tree", "unbounded", "per_file", "full_all_branches", "everything", "executive", None)
    assert q.passes == ["fast"] and d.runs_deep and a.runs_deep


def test_resolve_by_trigger_and_override():
    pol = {"on_pull_request": "standard", "on_default_branch": "deep", "on_release_tag": "audit"}
    assert depth.resolve(pol, trigger="pull_request").name == "standard"
    assert depth.resolve(pol, trigger="default_branch").name == "deep"
    assert depth.resolve(pol, trigger="release_tag").name == "audit"
    assert depth.resolve(pol, trigger="manual").name == "standard"
    assert depth.resolve(pol, trigger="default_branch", override="quick").name == "quick"
    assert depth.resolve(None).name == "standard"


def test_policy_profiles_override_dials_and_extend():
    profiles = {
        "standard": {"taint": {"mode": "cross_file_cached", "max_call_depth": 6}, "budget_minutes": 15, "probes": {"disable": {"jscpd": "monorepo too big"}}},
        "audit": {"extends": "deep", "licences": "per_file", "branches": ["main", "release/*"], "ai_triage": {"when": "all", "summary": "executive"}, "budget_minutes": None},
        "nightly": {"extends": "audit", "secrets_history": {"mode": "last_n", "last_n": 500}},
    }
    s = depth.build("standard", profiles)
    assert s.max_call_depth == 6 and s.budget_minutes == 15
    assert s.disabled_probes == {"jscpd": "monorepo too big"}
    a = depth.build("audit", profiles)
    assert a.taint_mode == "cross_file" and a.max_call_depth == 8  # inherited from deep
    assert a.licences == "per_file" and a.branches == ["main", "release/*"] and a.budget_minutes is None
    assert a.ai_triage == "all" and a.ai_summary == "executive"
    n = depth.build("nightly", profiles)
    assert n.name == "nightly" and n.secrets_history == "last_n" and n.secrets_last_n == 500 and n.licences == "per_file"


def test_bad_profiles_are_rejected():
    with pytest.raises(ValueError):
        depth.build("nope")
    with pytest.raises(ValueError):
        depth.build("a", {"a": {"extends": "b"}, "b": {"extends": "a"}})
