# ADR-0003: Native matchers first, Semgrep as an optional accelerator

- Status: Accepted
- Date: 2026-06-10

## Context

Static analysis is core to `scan`. Writing a full multi-language analyzer is out
of scope, and Semgrep is an excellent OSS engine with a rules ecosystem. But
requiring Semgrep would add a heavy, non-Go runtime dependency to a tool whose
selling point is being a single static binary that is trivial to adopt.

## Decision

Ship **native Go matchers as the always-on, authoritative analysis layer** for
high-signal patterns (remote-exec pipes, obfuscation, sensitive-path reads, exec
primitives, npm install hooks, prompt-injection language), each mapped to the
OWASP Agentic Skills Top 10 taxonomy.

Treat **Semgrep as an optional accelerator**: the `analyze.Semgrep` adapter
detects the binary on `PATH` and contributes additional findings when present.
When absent — or not yet wired — it is a no-op and never an error. Analyzers are
composed via `analyze.Chain`.

## Consequences

- `scan` works with zero external tools and produces credible results.
- Teams that install Semgrep get deeper coverage with no config change.
- Finding quality (false-positive rate) is tuned in the native ruleset, where we
  control severity and OWASP mapping directly.
- The Semgrep invocation/mapping is a documented seam to complete later.
