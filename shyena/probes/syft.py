"""Inventory: Syft builds the SBOM (CycloneDX JSON). Runs first; every dependency and
licence step reads its output through ``ScanContext.sbom_path`` / ``components``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shyena.models import Category, Component
from shyena.probes.base import CodeProbe, ProbeOutput, ScanContext

_DEV_HINTS = ("devDependencies", "dev", "test", "optional")


def _licence_of(comp: dict[str, Any]) -> str | None:
    ids: list[str] = []
    for entry in comp.get("licenses") or []:
        lic = entry.get("license") or {}
        if lic.get("id"):
            ids.append(lic["id"])
        elif lic.get("name"):
            ids.append(lic["name"])
        elif entry.get("expression"):
            ids.append(entry["expression"])
    return " AND ".join(dict.fromkeys(ids)) if ids else None


def _prop(comp: dict[str, Any], suffix: str) -> str | None:
    for p in comp.get("properties") or []:
        if str(p.get("name", "")).endswith(suffix):
            return p.get("value")
    return None


def components_from_cyclonedx(doc: dict[str, Any]) -> list[Component]:
    out: list[Component] = []
    for comp in doc.get("components") or []:
        purl = comp.get("purl")
        if not purl:
            continue
        ecosystem = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
        scope = (comp.get("scope") or "").lower()
        path = _prop(comp, ":location:0:path") or _prop(comp, "location:0:path") or ""
        out.append(
            Component(
                purl=purl,
                name=comp.get("name", ""),
                version=comp.get("version", ""),
                ecosystem=ecosystem,
                direct=None,
                dev=scope in ("optional", "excluded") or any(h in (_prop(comp, "dependencyType") or "") for h in _DEV_HINTS),
                licence_declared=_licence_of(comp),
                path=path,
            )
        )
    return out


class SyftProbe(CodeProbe):
    name = "syft"
    binary = "syft"
    description = "Software bill of materials for every package manager in the tree"
    install_hint = "https://github.com/anchore/syft#installation"
    category = Category.DEPENDENCY
    native_output = "CycloneDX"

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        sbom_path = workdir / "sbom.cdx.json"
        proc = self.exec(
            ["scan", f"dir:{ctx.repo.root}", "-o", f"cyclonedx-json={sbom_path}", "--quiet"],
            cwd=ctx.repo.root,
        )
        if proc.returncode != 0 or not sbom_path.exists():
            raise RuntimeError(f"syft exited {proc.returncode}: {proc.stderr.strip()[:500]}")
        doc = json.loads(sbom_path.read_text(encoding="utf-8"))
        components = components_from_cyclonedx(doc)
        out = ProbeOutput(components=components, inventory={"sbom_path": str(sbom_path), "sbom_format": "cyclonedx-json"})
        out.metrics["components"] = float(len(components))
        out.metrics["components_dev"] = float(sum(1 for c in components if c.dev))
        return out
