# agentguard

[![ci](https://github.com/alexverify/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/alexverify/agentguard/actions/workflows/ci.yml)

**Supply-chain integrity for AI coding tools.** A single static binary that
discovers every skill, MCP server, plugin, hook, and rule installed across your
AI coding tools, hashes them into a lockfile, statically scans them, and detects
post-audit modification — "rug pulls" — before they bite.

> Status: **early**. Component 1 (the read-only `scan`/`verify` wedge) is
> implemented and working. The runtime MCP firewall and team control plane are
> designed and seamed but not yet built. See
> [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md).

## Why

Skills, MCP servers, and hooks run with your privileges and can change after you
audit them. agentguard gives you a committable lockfile (`agentlock.json`) of
exactly what's installed and what it does, and tells you the moment any of it
changes.

## Install

Grab a static binary from the
[releases page](https://github.com/alexverify/agentguard/releases) (Linux and
macOS, amd64/arm64) and check it against the published `checksums.txt`:

```sh
shasum -a 256 -c --ignore-missing checksums.txt
```

Or build from source (requires Go 1.25+, nothing else):

```sh
make build   # → ./bin/agentguard
```

## Quickstart

```sh
make build            # builds ./bin/agentguard (zero external dependencies)

# From a project that uses Claude Code (has .mcp.json and/or .claude/skills):
./bin/agentguard scan          # discover, hash, analyze → writes agentlock.json
./bin/agentguard list          # pretty inventory across tools
./bin/agentguard verify        # recompute & diff vs the lockfile (rug-pull check)
./bin/agentguard verify --ci   # strict: apply the policy gate (see Policy below)
./bin/agentguard diff          # informational: what changed since the lockfile
./bin/agentguard approve <id>  # mark an artifact approved in the lockfile
./bin/agentguard sign          # sign the lockfile with your local ed25519 key
./bin/agentguard key show      # print your public key (share it with your team)
./bin/agentguard key trust <k> # trust a teammate's public key
./bin/agentguard wrap          # audit every MCP tool call via the stdio shim
./bin/agentguard wrap --status # what's wrapped + the real underlying commands
./bin/agentguard unwrap        # restore the original MCP config
```

Exit codes (stable for CI): `0` clean · `1` drift / findings over threshold ·
`2` usage error · `3` internal error.

The full solo and team workflows — policy, approvals, signing, trusted keys,
CI — are walked through in [docs/usage.md](docs/usage.md).

## Policy (CI gating)

`verify --ci` applies an optional `agentguard.policy.json` (commit it next to the
lockfile). Absent a file, the default gate fails on any **new** high/critical
finding. Example:

```jsonc
{
  "failOnSeverity": "high",          // gate on new findings at/above this severity
  "ignoreRules": ["EXEC-PRIMITIVE"], // accepted false positives, suppressed
  "requireApproval": true,           // fail any artifact not `agentguard approve`d
  "requireSignature": true,          // fail unless the lockfile is validly signed
  "mcp": {                           // runtime tool rules, enforced live by `wrap`
    "servers": { "github": { "denyTools": ["delete_*"] } }
  }
}
```

With `requireSignature`, the lockfile signature is checked against a
**trusted-keys registry**: `agentguard.trustedkeys` committed next to the
lockfile (one base64 ed25519 public key per line, optional label, `#` comments)
merged with your personal `~/.agentguard/trusted_keys`. Each teammate shares
their key with `agentguard key show` and registers others with
`agentguard key trust <key> --name alice --file agentguard.trustedkeys`. When no
registry declares any key, your own local key is trusted, so the single-user
flow needs no setup; once a registry exists it is authoritative — local
`verify --ci` behaves exactly like CI.

A committed lockfile + policy + trusted keys + the `verify --ci` exit code give
a small team "only approved, unmodified, clean, signed-by-us artifacts run
here" with no infrastructure.

### GitHub Action

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: alexverify/agentguard/action@v0.1.0
```

One tag pins the action and the checksum-verified binary it installs; see
[action/README.md](action/README.md) for inputs.

## Requirements

The binary itself has no runtime dependencies. To **pin and hash remote sources**
during a scan, agentguard shells out to the relevant tool:

- `npm` — to resolve `npx`/npm MCP servers to an exact version + integrity and
  fetch the package code.
- `git` — to resolve git sources to a commit SHA.

These are optional: if `npm`/`git` aren't on `PATH`, that source simply can't be
pinned and is recorded as a finding instead — the scan still completes. Local
paths, inline content, and remote-URL certificate pinning need nothing extra.

## What it detects today

- **Drift / rug pulls** — any artifact whose content hash, pinned version, npm
  integrity, or remote TLS certificate changed since you locked it.
- **High-signal static findings**, mapped to the OWASP Agentic Skills Top 10:
  remote-exec pipes (`curl … | sh`), obfuscation (`eval`/`atob`), sensitive-path
  reads (`~/.ssh`, `~/.aws`, `.env`), exec primitives, npm install hooks, and
  prompt-injection / consent-bypass language in skills and rules.
- **Unverifiable sources** — unpinned or remote sources are flagged rather than
  silently trusted.

## Architecture

Pragmatic **hexagonal (ports & adapters)** in idiomatic Go: a pure, exhaustively
tested domain core (the hashing and drift logic), application use-cases that
depend only on interfaces, and swappable adapters for every external surface.
The core leans on the **Go standard library** with a single, deliberate
exception — a TOML parser for Codex configs — because a supply-chain tool should
keep its own dependency surface auditable.

Read [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) for
the package map, data flow, testing strategy, and how to extend it (adding a
tool, resolver, or analyzer is a localized change behind one interface). The
key design choices and their trade-offs are written up in
[docs/architecture/decisions.md](docs/architecture/decisions.md).

## Development

```sh
make build    # build the binary
make test     # run all tests
make check    # gofmt + vet + tests (the local CI gate)
make help     # list all tasks
```

Requires Go 1.25+. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

| Component | What | Status |
|---|---|---|
| 1 — `scan`/`verify`/lockfile | Read-only inventory, hashing, analysis, drift, signing/trust, CI Action | **implemented** (Claude Code, Cursor, Gemini, OpenCode, Codex) |
| 2 — `wrap` | MCP interposition supervisor, OS sandbox, egress proxy + redaction | **in progress** — stdio shim with tool-call audit log + live policy enforcement |
| 3 — control plane | Policy API, audit log, approval workflow, dashboard | designed, seamed |

## License

[Apache-2.0](LICENSE).
