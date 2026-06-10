# ADR-0002: Standard-library-only core (zero external dependencies)

- Status: Accepted
- Date: 2026-06-10

## Context

agentguard polices software supply chains. Every dependency it pulls in is
itself supply-chain surface and a potential source of the very risk the tool
exists to detect. The MVP scope (discovery, hashing, native matchers, lockfile,
ed25519 signing, a CLI) is comfortably achievable with the Go standard library.

## Decision

The MVP core ships with **no third-party Go dependencies**. The CLI uses the
standard `flag` package with a small custom dispatcher instead of a framework
like cobra. JSON uses `encoding/json`; signing uses `crypto/ed25519`.

Future, genuinely hard parsers (tolerant JSONC, TOML) and the runtime-firewall
components (sandbox/proxy) may justify a vetted dependency — but each will be an
isolated, deliberate addition behind an existing seam, recorded in its own ADR.

## Consequences

- `go.mod` has no `require` block; the build is auditable to the byte and
  bulletproof offline. A strong trust signal for a security tool.
- We hand-roll small amounts of CLI plumbing rather than adopt a framework.
- The JSONC/TOML parsers are deferred (they currently return
  `ErrUnsupportedFormat`) rather than shipped via a dependency that isn't yet
  warranted; discovery degrades gracefully in the meantime.
