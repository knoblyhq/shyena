"""Runtime and framework detector, plus end-of-life status.

Reads manifests and lockfiles for the runtimes a project declares (Python, Node, PHP,
Go, Ruby, Java, Docker base images), records them in the inventory, and looks each up
on endoflife.date unless ``SHYENA_OFFLINE`` is set. End-of-life runtimes become
``compatibility`` findings; ones ending within the policy window become warnings.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from shyena.config import HTTP_TIMEOUT, offline
from shyena.models import Category, CodeFinding, Location, Severity
from shyena.probes.base import ProbeOutput, PythonCodeProbe, ScanContext

_PY_REQUIRES = re.compile(r'requires-python\s*=\s*["\']\s*[>=~^]*\s*(\d+\.\d+)')
_NODE_ENGINE = re.compile(r'"node"\s*:\s*"[^\d]*(\d+)(?:\.\d+)*')
_PHP_REQUIRE = re.compile(r'"php"\s*:\s*"[^\d]*(\d+\.\d+)')
_GO_DIRECTIVE = re.compile(r"^go\s+(\d+\.\d+)", re.MULTILINE)
_RUBY_VERSION = re.compile(r"^\s*ruby\s+['\"]~?>?\s*(\d+\.\d+)", re.MULTILINE)
_DOCKER_FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?([\w./-]+):([\w.-]+)", re.MULTILINE | re.IGNORECASE)
_JAVA_RELEASE = re.compile(r"<(?:maven\.compiler\.(?:release|source|target)|java\.version)>\s*(?:1\.)?(\d+)\s*<")

#: endoflife.date product slug -> (how we name it, cycle extractor)
_DOCKER_IMAGES = {"python": "python", "node": "nodejs", "php": "php", "golang": "go", "ruby": "ruby", "openjdk": "java", "eclipse-temurin": "java"}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def detect_runtimes(root: Path, manifests: list[str]) -> list[dict[str, str]]:
    """``[{product, cycle, source}]`` for every runtime a manifest pins."""
    found: list[dict[str, str]] = []

    def add(product: str, cycle: str, source: str) -> None:
        entry = {"product": product, "cycle": cycle, "source": source}
        if entry not in found:
            found.append(entry)

    for rel_path in manifests:
        path = root / rel_path
        name = path.name
        text = _read(path)
        if name == "pyproject.toml":
            m = _PY_REQUIRES.search(text)
            if m:
                add("python", m.group(1), rel_path)
        elif name == "package.json":
            m = _NODE_ENGINE.search(text)
            if m:
                add("nodejs", m.group(1), rel_path)
        elif name == "composer.json":
            m = _PHP_REQUIRE.search(text)
            if m:
                add("php", m.group(1), rel_path)
        elif name == "go.mod":
            m = _GO_DIRECTIVE.search(text)
            if m:
                add("go", m.group(1), rel_path)
        elif name == "Gemfile":
            m = _RUBY_VERSION.search(text)
            if m:
                add("ruby", m.group(1), rel_path)
        elif name == "pom.xml":
            m = _JAVA_RELEASE.search(text)
            if m:
                add("java", m.group(1), rel_path)
        elif name == "Dockerfile":
            for image, tag in _DOCKER_FROM.findall(text):
                product = _DOCKER_IMAGES.get(image.split("/")[-1])
                m = re.match(r"(\d+(?:\.\d+)?)", tag)
                if product and m:
                    cycle = m.group(1) if product in ("python", "php", "go", "ruby") else m.group(1).split(".")[0]
                    add(product, cycle, rel_path)
    for marker, product in ((".python-version", "python"), (".nvmrc", "nodejs"), (".node-version", "nodejs"), (".ruby-version", "ruby")):
        path = root / marker
        if path.is_file():
            m = re.search(r"(\d+(?:\.\d+)?)", _read(path))
            if m:
                cycle = m.group(1) if product in ("python", "ruby") else m.group(1).split(".")[0]
                add(product, cycle, marker)
    return found


def lookup_eol(product: str, cycle: str) -> dict[str, Any] | None:
    """``{eol: date|None, latest: str}`` from endoflife.date, or None when unknown/offline."""
    if offline():
        return None
    url = f"https://endoflife.date/api/{product}/{cycle}.json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "shyena/0.0"}), timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    eol_raw = data.get("eol")
    eol: date | None = None
    if isinstance(eol_raw, str):
        try:
            eol = date.fromisoformat(eol_raw)
        except ValueError:
            eol = None
    elif eol_raw is True:
        eol = date.today() - timedelta(days=1)
    return {"eol": eol, "latest": str(data.get("latest", "")), "lts": data.get("lts", False)}


class ManifestsProbe(PythonCodeProbe):
    name = "manifests"
    description = "Runtime and framework versions from manifests, with end-of-life status"
    category = Category.COMPATIBILITY

    def wanted(self, profile) -> bool:
        return profile.compatibility

    def scan(self, ctx: ScanContext, workdir: Path) -> ProbeOutput:
        runtimes = detect_runtimes(ctx.repo.root, ctx.repo.manifests)
        out = ProbeOutput(inventory={"runtimes": runtimes, "languages": ctx.repo.languages, "manifests": ctx.repo.manifests})
        out.metrics["runtimes"] = float(len(runtimes))
        window = timedelta(days=int(ctx.policy.get("compatibility", {}).get("warn_on_eol_within_days", ctx.depth.eol_within_days)))
        today = date.today()
        checked = 0
        for rt in runtimes:
            info = lookup_eol(rt["product"], rt["cycle"])
            if info is None:
                continue
            checked += 1
            rt["eol"] = info["eol"].isoformat() if info["eol"] else None
            rt["latest"] = info["latest"]
            eol = info["eol"]
            if eol is None:
                continue
            label = f"{rt['product']} {rt['cycle']}"
            loc = [Location(path=rt["source"])]
            if eol <= today:
                out.findings.append(
                    CodeFinding(
                        title=f"{label} reached end-of-life on {eol.isoformat()}",
                        severity=Severity.HIGH,
                        target=ctx.target,
                        probe=self.name,
                        description=f"Declared in {rt['source']}. No security fixes are published for this runtime any more.",
                        remediation=f"Upgrade to a supported release (latest: {info['latest'] or 'see endoflife.date'}).",
                        references=[f"https://endoflife.date/{rt['product']}"],
                        rule_id="shyena:eol.runtime",
                        category=Category.COMPATIBILITY,
                        locations=loc,
                    )
                )
            elif eol - today <= window:
                out.findings.append(
                    CodeFinding(
                        title=f"{label} reaches end-of-life on {eol.isoformat()}",
                        severity=Severity.MEDIUM,
                        target=ctx.target,
                        probe=self.name,
                        description=f"Declared in {rt['source']}. {(eol - today).days} days of support remain.",
                        remediation="Plan the upgrade before the date.",
                        references=[f"https://endoflife.date/{rt['product']}"],
                        rule_id="shyena:eol.soon",
                        category=Category.COMPATIBILITY,
                        locations=loc,
                    )
                )
        if runtimes and checked == 0:
            out.note = "end-of-life lookup skipped (offline or unreachable)"
        elif not runtimes:
            out.note = "no runtime pins found in manifests"
        return out
