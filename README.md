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

| Engine | Dimension | Install | Status |
| --- | --- | --- | --- |
| Syft | SBOM (runs first) | `winget install Anchore.Syft` / brew / apt | proven on a production app |
| Semgrep | code vulnerabilities, our rules in `shyena/rules/semgrep` | `pip install semgrep` | proven on a production app |
| Grype | dependency vulnerabilities over the SBOM | `winget install Anchore.Grype` / brew / apt | proven on a production app |
| Trivy | Dockerfile / Terraform / Kubernetes misconfiguration | `winget install AquaSecurity.Trivy` / brew / apt | proven on a Dockerfile + Terraform fixture |
| Gitleaks | secrets (value never stored, only its hash) | `winget install Gitleaks.Gitleaks` / brew | proven on a production app's full history |
| Lizard | cyclomatic complexity | `pip install lizard` | proven on a production app |
| jscpd | duplication | `npm i -g jscpd` | adapter unit-tested only |
| manifests | runtime versions + end-of-life (endoflife.date) | built in | proven |
| licence-policy | licence compatibility over the SBOM | built in | proven |

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

## Handing a scan to the repository's own session

A scan is most useful in the hands of whoever works on that codebase. Write a short
handoff next to the run (what was scanned, the gate result, where the files are, which
findings were checked by eye and which were not, how to re-scan and mark findings),
and start a Claude session in the target repository with "read the handoff first;
verify the high findings before changing code".

Keep handoffs with the run or in the target repository, **never in this one**: they
describe another codebase's open weaknesses and, for secrets, where the live keys are.
`docs/handoffs/` is gitignored for that reason.

## Java and Spring Boot

`shyena/rules/semgrep/java/` holds 30 rules for Spring MVC / Spring Boot services on
PostgreSQL and Redis:

| Area | Rules |
| --- | --- |
| Request data to a sink (intra-file taint from any `@GetMapping`/`@PostMapping`/... parameter or `HttpServletRequest`) | `sqli-taint` (JdbcTemplate, JdbcClient, JPA/Hibernate, JDBC, R2DBC, jOOQ), `spel-injection`, `command-injection`, `ssrf` (RestTemplate, WebClient, RestClient, URL), `path-traversal` (incl. `MultipartFile.getOriginalFilename()`), `open-redirect`, `redis-lua-injection` |
| SQL built at run time anywhere (no taint, so it reaches repositories and DAOs; WARNING, does not fail the gate) | `sql-non-constant` |
| MyBatis | `mybatis-dollar-substitution` (`${}` in mapper XML), `mybatis-annotation-dollar-substitution` (`@Select` etc.) |
| PostgreSQL | `postgres-weak-sslmode`, `postgres-superuser-login`, `postgres-dangerous-function` (COPY ... PROGRAM, server files, `lo_import`, `pg_read_file`, dblink; in Java and in migrations) |
| Redis | `redis-jdk-serialization` (JDK serializer, or RedisTemplate / RedisCacheConfiguration left on the default), `redis-no-tls` |
| Unsafe parsing | `unsafe-deserialization` (ObjectInputStream, XMLDecoder, XStream), `jackson-polymorphic-typing`, `xxe` |
| Spring Security | `spring-csrf-disabled`, `spring-permit-all-catch-all`, `spring-cors-any-origin` |
| Crypto and keys | `insecure-tls` (trust-all managers, no-op hostname verifiers), `weak-password-encoder`, `weak-crypto`, `hardcoded-jwt-secret` |
| `application*.properties` / `.yml` | `spring-actuator-exposed`, `spring-h2-console-enabled`, `spring-secret-in-config` |
| Thymeleaf templates | `thymeleaf-unescaped-text` (`th:utext`, `[(...)]`) |

The manifest probe reads the Java release and the Spring Boot version from `pom.xml`,
`build.gradle` and `build.gradle.kts` and checks both against endoflife.date (Java via
Eclipse Temurin's support dates, since endoflife.date has no generic Java entry).
Dependency CVEs (Grype over the Syft SBOM), secrets (Gitleaks), complexity (Lizard) and
duplication (jscpd) need nothing Java-specific.

Limits: taint does not cross files; `sql-non-constant` is the safety net for that, at
the cost of some noise (IN lists built in a loop, table names from config). Numeric,
UUID and date handler parameters are treated as safe. Not covered: authorization
(missing `@PreAuthorize`, IDOR), mass assignment, sensitive data in logs, Spring
Session's serializer (configured by bean name), and Kotlin. Profile files named
`application-dev*`, `-local*` and `-test*` are exempt from the Postgres and Redis
transport rules. Every rule is proven by `tests/test_rules.py` against
annotated fixtures in `tests/rules/semgrep/java/` (`// ruleid:` must fire, `// ok:` must not).

## Phase 0 status

Built and tested: the contract (`CodeProbe`, `ScanContext`, `ProbeOutput`), the
finding model, fingerprints, SARIF in/out, eight probe adapters, the licence policy
engine, depth presets, gate evaluation, lifecycle and reviewer decisions, reports,
the CLI, nine Semgrep rules of our own (PHP, JavaScript, Python) and a Java / Spring
Boot pack of twenty more (see below).

Verified against live engine output: Semgrep, Lizard, Syft, Grype and Gitleaks on
a production PHP application (600 files; about 30 seconds at standard depth, 3.5
minutes at deep depth where Gitleaks walks the whole history), Trivy on a Dockerfile +
Terraform fixture (that application has no container or IaC files for it to judge),
and Semgrep + Lizard on the vulnerable
fixture in `tests/test_real_engines.py`, which runs when the binaries are present. The
test suite otherwise pretends no engines are installed, so it passes on a bare machine.

Not yet exercised against live output: the jscpd adapter. Next: the Claude / Ollama
triage providers and the API server (Phase 1).

### Things learned on Windows

- Grype's vulnerability database is about 3 GB and Trivy's checks bundle a few hundred
  MB; on a full C: drive point `GRYPE_DB_CACHE_DIR` and `TRIVY_CACHE_DIR` at another
  disk (`setx`), otherwise the first scan fails mid-download.
- winget installs put their aliases in `%LOCALAPPDATA%\Microsoft\WinGet\Links`; a
  shell started before the install, or a non-login Git Bash, may not have it on PATH.

- Semgrep's `by-side-effect: true` sanitisers do not fire for PHP (1.180), so the
  rules guard sinks with `pattern-not-inside: if (<... preg_match(...) ...>) { ... }`.
- Semgrep prefixes rule ids with the config directory path; the probe strips it back
  to `shyena.<lang>.<rule>`.
- The cp1252 console cannot print arrows or ticks; CLI output is ASCII, and a failing
  progress hook never aborts a scan.
