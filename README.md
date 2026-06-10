# agentguard

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

## Quickstart

```sh
make build            # builds ./bin/agentguard (zero external dependencies)

# From a project that uses Claude Code (has .mcp.json and/or .claude/skills):
./bin/agentguard scan          # discover, hash, analyze → writes agentlock.json
./bin/agentguard list          # pretty inventory across tools
./bin/agentguard verify        # recompute & diff vs the lockfile (rug-pull check)
./bin/agentguard verify --ci   # strict: also fail on new high/critical findings
./bin/agentguard diff          # informational: what changed since the lockfile
./bin/agentguard approve <id>  # mark an artifact approved in the lockfile
```

Exit codes (stable for CI): `0` clean · `1` drift / findings over threshold ·
`2` usage error · `3` internal error.

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
The MVP core uses **only the Go standard library** — a supply-chain tool should
be auditable to the byte.

Read [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) for
the package map, data flow, testing strategy, and how to extend it (adding a
tool, resolver, or analyzer is a localized change behind one interface).
Decisions are recorded as [ADRs](docs/architecture/adr/).

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
| 1 — `scan`/`verify`/lockfile | Read-only inventory, hashing, analysis, drift | **implemented** (Claude Code; more tools seamed) |
| 2 — `wrap` | MCP interposition supervisor, OS sandbox, egress proxy + redaction | designed, seamed |
| 3 — control plane | Policy API, signature/trust registry, audit log, CI Action, dashboard | designed, seamed |

## License

[Apache-2.0](LICENSE).
