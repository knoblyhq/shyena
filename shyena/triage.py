"""AI triage layer: one ``Triager`` interface, pluggable providers.

Phase 0 ships the null provider only. Claude (SaaS) and Ollama (on-prem) providers
are the next step; the interface, guardrails and selection logic are fixed here so
the engine does not change when they land.

Guardrails (from the architecture note):
1. AI sees the finding, its rule text and the surrounding code only, never the whole tree.
2. It returns a verdict, a confidence, an explanation and a suggested fix — it never
   edits code.
3. A false-positive verdict demotes a finding; it never deletes one.
4. AI can lift a fail to a pass (by demotion) only when the policy allows; it never
   turns a pass into a fail.
5. Every call is recorded with model and prompt version, append-only.
"""

from __future__ import annotations

from typing import Any, Protocol

from shyena.depth import DepthProfile
from shyena.models import CodeFinding, FindingStatus, Severity, Triage
from shyena.policy import severity_at_least

PROMPT_VERSION = "shyena-triage/0.1"


class Triager(Protocol):
    name: str

    def available(self) -> bool: ...

    def triage(self, finding: CodeFinding, context: dict[str, Any]) -> Triage | None: ...


class NullTriager:
    """Does nothing; the scan proceeds exactly as the engines reported it."""

    name = "null"

    def available(self) -> bool:
        return True

    def triage(self, finding: CodeFinding, context: dict[str, Any]) -> Triage | None:
        return None


class ClaudeTriager:
    """Claude via the Anthropic API. Not wired in Phase 0."""

    name = "claude"

    def available(self) -> bool:
        return False

    def triage(self, finding: CodeFinding, context: dict[str, Any]) -> Triage | None:
        raise NotImplementedError("Claude triage lands with the API server (Phase 1)")


class OllamaTriager:
    """A local model via Ollama for on-prem deployments. Not wired in Phase 0."""

    name = "ollama"

    def available(self) -> bool:
        return False

    def triage(self, finding: CodeFinding, context: dict[str, Any]) -> Triage | None:
        raise NotImplementedError("Ollama triage lands with the on-prem build (Phase 1)")


_PROVIDERS = {"null": NullTriager, "claude": ClaudeTriager, "ollama": OllamaTriager}


def select(profile: DepthProfile) -> Triager:
    """The provider the profile asks for, falling back to null when it is off or
    unavailable (the fallback is recorded in the scan's probe runs by the engine)."""
    if profile.ai_triage == "off":
        return NullTriager()
    cls = _PROVIDERS.get(profile.ai_provider, NullTriager)
    triager = cls()
    return triager if triager.available() else NullTriager()


def candidates(findings: list[CodeFinding], profile: DepthProfile, policy_threshold: str) -> list[CodeFinding]:
    """Which findings go to the AI layer under this profile."""
    mode = profile.ai_triage
    if mode == "off":
        return []
    if mode == "everything":
        return list(findings)
    new = [f for f in findings if f.status is FindingStatus.NEW]
    if mode == "all_new":
        return new
    threshold = severity_at_least(profile.ai_threshold or policy_threshold)
    return [f for f in new if f.severity in threshold]


def run(triager: Triager, findings: list[CodeFinding], context: dict[str, Any]) -> int:
    """Triage each finding in place; returns how many got a verdict."""
    done = 0
    for f in findings:
        verdict = triager.triage(f, {**context, "finding": f.to_dict()})
        if verdict is not None:
            f.triage = verdict
            done += 1
    return done


__all__ = [
    "Triager",
    "NullTriager",
    "ClaudeTriager",
    "OllamaTriager",
    "select",
    "candidates",
    "run",
    "PROMPT_VERSION",
    "Severity",
]
