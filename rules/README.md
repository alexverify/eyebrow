# rules/ — Semgrep accelerator pack

Curated [Semgrep](https://semgrep.dev) rules that deepen `assay scan`'s
static analysis with language-aware checks the native regex matchers can't
express (e.g. `shell=True` subprocess calls, env-serialization exfil shapes,
interpolated `child_process` exec).

This layer is **optional and soft** by contract:

- No `semgrep` on `PATH` → contributes nothing, never errors.
- Rules dir absent (`--rules`, default `./rules`) → silent no-op.
- Semgrep crash or unparseable output → silent no-op.

The native matchers (internal/adapters/analyze/native.go) remain authoritative;
they carry the critical-severity rules and require nothing but the binary.

## Severity & taxonomy mapping

| Semgrep | assay |
|---|---|
| `ERROR` | high |
| `WARNING` | medium |
| `INFO` | low |

Critical is reserved for native rules — a semgrep rule that warrants critical
impact should be promoted to a native matcher. Each rule's
`metadata.owasp-agentic` (e.g. `ASK-01`) flows into the finding's OWASP field.
Rule IDs surface namespaced as `SEMGREP-<ID>` (e.g. `SEMGREP-SUBPROCESS-SHELL-TRUE`)
so they can be suppressed independently in `assay.policy.json` `ignoreRules`.

## Validating changes

```sh
semgrep scan --validate --config rules/   # or: uvx semgrep scan --validate --config rules/
```

`internal/adapters/analyze/semgrep_test.go` guards the file format and the
adapter's JSON mapping with a scripted runner — no semgrep needed for `make check`.
