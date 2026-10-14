# Shyena

Shyena (श्येन, the sharp-eyed hawk of the Rigveda) profiles a codebase on six dimensions
in one scan — **code vulnerabilities, dependency vulnerabilities, licences, secrets,
code smell, compatibility** — and judges only the code that changed.

It is the `code` module of the Knobly GRC platform: every engine is a GRC `Probe`,
every result is a GRC `Finding`, every scan is a GRC test instance. The GRC core
(`vapt` package, `D:\vapt`) supplies the probe contract, the finding model, run
persistence, reports and the dashboard; Shyena adds the engines, the SARIF
normaliser, stable fingerprints, the clean-as-you-code gate, the YAML policy, the
depth configurator and the AI triage interface.

- Architecture note: https://claude.ai/code/artifact/7fd8655d-4b6e-4120-a2df-cabf17192380 (Word export in `docs/`)
- Policy file: `.shyena.yml` at the repository root · CLI: `shyena scan`

## Install

```bash
python -m pip install -e D:\vapt          # the GRC core (not on PyPI)
python -m pip install -e .[dev]           # shyena + pytest
shyena tools                              # which engines are installed
```

Engines are open-source binaries invoked as processes; a missing one skips cleanly
and the report says so. Locations resolve from `VAPT_<NAME>_PATH`, then `tools.json`
in the state directory, then `PATH`.

| Engine | Dimension | Install |
| --- | --- | --- |
| Syft | SBOM (runs first) | https://github.com/anchore/syft |
| Semgrep | code vulnerabilities, our rules in `shyena/rules/semgrep` | `pip install semgrep` |
| Grype | dependency vulnerabilities over the SBOM | https://github.com/anchore/grype |
| Trivy | Dockerfile / Terraform / Kubernetes misconfiguration | https://trivy.dev |
| Gitleaks | secrets (value never stored, only its hash) | https://github.com/gitleaks/gitleaks |
| Lizard | cyclomatic complexity | `pip install lizard` |
| jscpd | duplication | `npm i -g jscpd` |
| manifests | runtime versions + end-of-life (endoflife.date) | built in |
| licence-policy | licence compatibility over the SBOM | built in |

## Usage

```bash
shyena scan .                                   # first scan: whole tree (onboarding)
shyena scan . --base origin/main                # a pull request: only new findings on changed lines gate
shyena scan . --depth deep --trigger default_branch
shyena scan . --json                            # summary for CI; exit 1 when the gate fails
shyena list
shyena show <id> [--all]
shyena policy . --depth audit                   # effective policy + resolved depth dials
shyena mark <fingerprint> --status accepted --reason "legacy, tracked in JIRA-12"
```

State lives under `SHYENA_HOME` (defaults to the GRC core's `VAPT_HOME`, else the
working directory): `runs/<id>/` holds `instance.json` (core view), `scan.json`,
`results.sarif`, `summary.json`, `report.md` and `raw/`. `SHYENA_OFFLINE=1` skips
every network lookup.

## Pipeline

1. Inspect the tree: commit, base (merge-base), changed files, languages, manifests.
2. Inventory: Syft SBOM, manifest detector.
3. Fast pass: every selected probe, isolated and checkpointed, within the time budget.
4. Normalise: SARIF or a thin JSON mapper → `CodeFinding`.
5. Fingerprint and classify: new / recurring / fixed against the baseline scan;
   reviewer decisions (accepted, false positive) applied by fingerprint.
6. Triage with AI (null provider in Phase 0; Claude and Ollama next).
7. Evaluate the gate from `.shyena.yml`.
8. Report: SARIF bundle, JSON summary, Markdown, plus the GRC core's reports.

## Layout

```
shyena/
  models.py      CodeFinding (GRC Finding + rule, category, locations, trace, component,
                 licence, confidence, status, triage, introduced_commit), Component, ScanRun
  fingerprint.py stable SHA-256 fingerprints (line-shift and whitespace tolerant)
  sarif.py       SARIF 2.1.0 reader + bundle writer
  repo.py        git facts: changed files/lines, blame, languages, manifests
  depth.py       Quick / Standard / Deep / Audit presets and the ten dials
  policy.py      .shyena.yml loader, licence categoriser, gate evaluation
  classify.py    lifecycle + clean-as-you-code eligibility
  triage.py      Triager interface, null provider, guardrails
  engine.py      the pipeline
  store.py       scan.json + reviewer decisions
  report.py      SARIF / JSON / Markdown
  probes/        one adapter per engine, registry in __init__.py
  rules/semgrep/ our rule set
tests/           pytest, no engines or network needed
```

## Phase 0 status

Built and tested: the contract (`CodeProbe`, `ScanContext`, `ProbeOutput`), the
finding model, fingerprints, SARIF in/out, eight probe adapters, the licence policy
engine, depth presets, gate evaluation, lifecycle and reviewer decisions, reports,
the CLI. Verified end-to-end on a repository with only the pure-Python probes.

Not yet exercised against real engine output: the Syft, Grype, Trivy, Gitleaks,
Lizard and jscpd adapters need the binaries installed and a run on a real repository.
Next: install the engines, scan one of our own repositories, then the Claude / Ollama
triage providers and the API server (Phase 1).
