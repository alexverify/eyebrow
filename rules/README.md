# rules/ — Semgrep rules pack (seam)

A versioned Semgrep ruleset used by the optional Semgrep analyzer
(`internal/adapters/analyze/semgrep.go`). Empty today.

## Plan

- Per-language rules (JS/TS, Python, shell, Go) for MCP/skill security patterns:
  remote code execution, exfiltration, consent-bypass, sensitive-path access.
- Start by adapting public MCP/skill security rules; add custom rules for the
  consent-bypass and exfil patterns the native matchers can't express.
- Every rule maps to an OWASP Agentic Skills Top 10 category and a severity, so
  Semgrep findings merge cleanly with native findings.

## How it's wired

`analyze.NewSemgrep("rules")` resolves the `semgrep` binary on `PATH` and (once
implemented) runs `semgrep --json --config rules/ <artifact>`, mapping results
to `finding.Finding`. When semgrep is absent it contributes nothing — the native
matchers remain authoritative. See
[ADR-0003](../docs/architecture/adr/0003-semgrep-optional-accelerator.md).
