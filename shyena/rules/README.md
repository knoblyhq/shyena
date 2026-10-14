# Shyena rule sets

Our own rules, run by the open-source Semgrep engine (LGPL 2.1, invoked as a process).
The Semgrep registry is **not** used: its rules carry a licence we cannot ship.

Layout: `semgrep/<language>/<rule-name>.yml`, one rule per file, id
`shyena.<language>.<rule-name>`.

Tags in `metadata.category` route a rule to a dimension: `security` (default) →
vulnerability, `smell` → code smell, `deprecated` → compatibility.

Phase 0 ships one rule per supported language as a template. The rule set grows per
client engagement; keep CWE and a reference on every rule.
