# Shyena rule sets

Our own rules, run by the open-source Semgrep engine (LGPL 2.1, invoked as a process).
The Semgrep registry is **not** used: its rules carry a licence we cannot ship.

Layout: `semgrep/<language>/<rule-name>.yml`, one rule per file, id
`shyena.<language>.<rule-name>`.

Tags in `metadata.category` route a rule to a dimension: `security` (default) →
vulnerability, `smell` → code smell, `deprecated` → compatibility.

Related rules may share a file (the Java taint rules share one definition of request
data through a YAML anchor in `java/request-taint.yml`). Keep CWE and a reference on
every rule.

Every rule needs a positive fixture under `tests/rules/semgrep/<language>/`: a comment
`ruleid: <id>` marks a line the rule must report, `ok: <id>` one it must not.
`tests/test_rules.py` scans a temporary copy of the fixtures (Semgrep's default ignore
list skips `tests/`, so `semgrep --test` in place passes vacuously) and fails on any
missed, extra or uncovered rule.
