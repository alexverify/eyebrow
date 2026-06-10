# Design decisions

Short notes on the choices that shape the codebase and the trade-offs behind
them. If you're about to change one of these, read the relevant note first —
each one exists for a reason that isn't obvious from the code alone.

## Ports and adapters, not layered "Clean Architecture"

The core — content hashing and drift detection — is pure Go with no IO.
Everything that touches npm, git, TLS, or the filesystem sits behind an
interface in `internal/app/ports`, and dependencies only ever point inward
(`cmd` → `cli` → `adapters` → `app` → `domain`).

We deliberately skipped the heavier entities/use-cases/interface-adapters/
frameworks layout you see in formal Clean Architecture write-ups. In Go it adds
indirection without paying for itself. The payoff we actually wanted is concrete:
the trust-critical logic is unit-tested with no disk or network, and any messy
external surface can be faked in a test or swapped in production without touching
the core.

## Standard library only (for now)

`go.mod` has no `require` block. The CLI uses `flag`, config parsing uses
`encoding/json`, signing uses `crypto/ed25519`. For a tool whose entire job is
auditing supply chains, every dependency we pull in is both attack surface and a
credibility problem — "audit your dependencies" reads badly from a binary with a
hundred of its own.

The cost is real and accepted: we hand-roll small things like CLI dispatch, and
JSONC parsing is a hand-rolled, string-aware stripper feeding `encoding/json`.

**The one exception so far:** TOML parsing for Codex configs uses
`github.com/BurntSushi/toml`. TOML has enough edge cases (quoting, dotted keys,
multiline strings, inline tables) that a hand-rolled subset reader would be a
latent source of mis-parses — exactly what a security tool must not ship. So we
made the deliberate call to pull in the de-facto standard, well-audited library,
isolated to the `parse` adapter. That's the bar for any future dependency: only
when hand-rolling is a correctness risk, and always behind an existing seam.

## Native matchers are the analyzer; Semgrep is optional

`scan` has to work the moment you download the binary, so the built-in Go
matchers (`internal/adapters/analyze`) are the source of truth for findings, each
mapped to an OWASP Agentic Skills Top 10 category. If `semgrep` happens to be on
`PATH`, the optional adapter layers on extra coverage; if it isn't, that adapter
is a silent no-op, never an error. This keeps the zero-dependency promise while
leaving room for a richer ruleset later.

Analysis skips vendored dependency directories (`node_modules`, `.venv`,
`site-packages`, `*.dist-info`, …) — flagging pip's or PIL's internals buries the
findings that matter in the skill author's own code. Hashing, deliberately, does
*not* skip them: vendored code still runs, so it stays part of the integrity
anchor.

## ed25519 signatures now, cosign/Sigstore later

Lockfiles and per-artifact approvals are signed with detached ed25519
(`crypto/ed25519`, no dependencies), encoded as `ed25519:<base64>` so the scheme
is self-describing. The mature industry answer is cosign keyless signing, but it
drags in infrastructure we don't need at this stage. Signing lives behind
`ports.Signer`, so a cosign adapter can replace it later with a `cosign:` prefix
and zero changes to callers.

## How each source kind gets pinned

A lockfile is only worth anything if we know exactly which bytes run. There's no
single way to pin that, so resolution (`internal/adapters/resolve`) differs by
source:

- **npm** — pin the exact version and reuse npm's own `dist.integrity` (sha512)
  rather than recomputing it; fetch the tarball so we can hash the real code.
- **git** — pin a commit SHA via `git ls-remote`; the SHA *is* the anchor.
- **url** — remote code can't be hashed, so pin the server's TLS certificate
  (its SPKI hash). A cert rotation shows up as drift; that's the honest ceiling
  for code we don't host.
- **local / inline** — hash the files or the literal content directly.

Anything we can't pin — an unreachable registry, an `@latest` tag, `npm` not
installed — becomes a finding rather than aborting the scan. A security tool that
breaks a developer's workflow gets uninstalled, so degrading loudly beats failing
hard.
