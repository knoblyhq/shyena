"""Probe registry for the ``code`` scope.

Explicit, like the GRC core's registry: import a probe, add an instance. The order is
the pipeline order — inventory first (every later step reads the SBOM), then the fast
pass, then deep-pass engines.
"""

from __future__ import annotations

from shyena.depth import DepthProfile
from shyena.probes.base import CodeProbe
from shyena.probes.gitleaks import GitleaksProbe
from shyena.probes.grype import GrypeProbe
from shyena.probes.jscpd import JscpdProbe
from shyena.probes.lizard import LizardProbe
from shyena.probes.manifests import ManifestsProbe
from shyena.probes.semgrep import SemgrepProbe
from shyena.probes.syft import SyftProbe
from shyena.probes.trivy import TrivyProbe


def all_probes() -> list[CodeProbe]:
    """Every known probe, available or not, in pipeline order."""
    return [
        SyftProbe(),
        ManifestsProbe(),
        SemgrepProbe(),
        GrypeProbe(),
        TrivyProbe(),
        GitleaksProbe(),
        LizardProbe(),
        JscpdProbe(),
    ]


def probes_for(profile: DepthProfile, *, available_only: bool = True) -> list[CodeProbe]:
    """Probes that run under ``profile``: right pass, not disabled, installed."""
    selected: list[CodeProbe] = []
    for probe in all_probes():
        if probe.scan_pass.value not in profile.passes:
            continue
        if probe.name in profile.disabled_probes:
            continue
        if not probe.wanted(profile):
            continue
        if available_only and not probe.is_available():
            continue
        selected.append(probe)
    return selected
