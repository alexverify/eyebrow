# agentguard architecture

How the codebase is organized, how a scan actually runs, and where to add code.
Start here if you're contributing. For *why* things are built this way, see
[decisions.md](decisions.md); for what the tool does, see the [README](../../README.md).

## What agentguard is

A single static binary that brings supply-chain integrity to AI coding tools.
It discovers every skill, MCP server, plugin, hook, and rule installed across
tools like Claude Code, hashes them into a lockfile, statically scans them, and
detects post-audit modification ("rug pulls"). Later components add a runtime
MCP firewall and a team control plane; this codebase implements **Component 1**
(the read-only wedge) and lays clean seams for the rest.

## Architectural style: pragmatic hexagonal

We use **ports and adapters** (hexagonal architecture) in an idiomatic Go form.
The system is three concentric responsibilities, and **all dependencies point
inward**:

```
            ┌─────────────────────────────────────────────┐
            │                  adapters                     │
            │  cli · discover · resolve · hash · analyze    │
            │  lockstore · report · sign   (driven + driving)│
            │      ┌─────────────────────────────────┐      │
            │      │           application            │      │
            │      │     scan · verify · ports        │      │
            │      │      ┌───────────────────┐       │      │
            │      │      │      domain        │       │      │
            │      │      │ artifact · finding │       │      │
            │      │      │ digest · lockfile  │       │      │
            │      │      └───────────────────┘       │      │
            │      └─────────────────────────────────┘      │
            └─────────────────────────────────────────────┘
              dependencies only ever point toward the center
```

- **domain** (`internal/domain`) — pure Go, **zero IO and zero third-party
  imports**. The trust-critical primitives: the `Artifact` model, the
  `Finding`/`Severity`/OWASP taxonomy, the canonical Merkle **digest**
  algorithm, and the lockfile **diff/drift** logic. Deterministic and
  exhaustively unit-testable.
- **application** (`internal/app`) — use-case services (`scan`, `verify`) that
  orchestrate the workflow. They depend only on the domain and on **ports**
  (interfaces they declare). They know nothing about npm, Semgrep, the
  filesystem, or the CLI.
- **adapters** (`internal/adapters`, `internal/cli`) — implement the ports. The
  *driving* adapter is the CLI; *driven* adapters are discovery, resolution,
  hashing, analysis, lockfile storage, signing, and reporting.

Why this matters for a security tool: the logic that decides "did these bytes
change" is pure and tested in isolation, while every messy external surface (a
shelled-out `npm view`, a Semgrep call, a config parser) sits behind an
interface that can be faked, swapped, or degraded without touching the core.

## Package map

| Package | Layer | Responsibility |
|---|---|---|
| `internal/domain/artifact` | domain | Normalized model for every discovered item; stable ID derivation. |
| `internal/domain/finding` | domain | Static-analysis result type, severity ranking, OWASP mapping. |
| `internal/domain/digest` | domain | Canonical Merkle content digest (pure, IO-free). |
| `internal/domain/lockfile` | domain | Lockfile model, deterministic `Build`, and `Compare` (the rug-pull detector). |
| `internal/app/ports` | application | All interface definitions + sentinel errors + `Scope`. |
| `internal/app/scan` | application | `scan` use case: discover → resolve → hash → analyze → lock. |
| `internal/app/verify` | application | `verify` use case: recompute → diff → gate. |
| `internal/app/apptest` | application | In-memory fakes implementing every port, for tests. |
| `internal/adapters/discover` | adapter | Per-tool config discovery: Claude Code (MCP, skills, subagents, hooks, context), Cursor (MCP, rules), Gemini (MCP), OpenCode (MCP), Codex (MCP, context). |
| `internal/adapters/parse` | adapter | Config normalizers: JSON, JSONC (hand-rolled), TOML (BurntSushi). |
| `internal/adapters/resolve` | adapter | Source → concrete pinned code: local, inline, npm, git, url. |
| `internal/adapters/hash` | adapter | Filesystem walk feeding the domain digest. |
| `internal/adapters/analyze` | adapter | Native high-signal matchers + optional Semgrep accelerator. |
| `internal/adapters/lockstore` | adapter | Atomic, deterministic `agentlock.json` read/write. |
| `internal/adapters/sign` | adapter | ed25519 detached signatures. |
| `internal/adapters/report` | adapter | Text and JSON reporters. |
| `internal/cli` | adapter (driving) | Argument parsing, composition root, exit-code mapping. |
| `internal/platform/run` | shared | Command-runner abstraction for shelling out (npm/git), with a fake. |
| `internal/buildinfo` | shared | Build-time version metadata. |
| `cmd/agentguard` | entrypoint | Thin `main`: signal handling, hand off to the CLI. |

## Data flow

**`scan`** — `internal/app/scan`:

```
Discoverer.Discover(scopes)        → []Artifact (config-level declarations)
  └─ for each artifact:
       Resolver.Resolve(source)    → concrete code on disk + integrity anchor
                                       (npm pkg@ver+integrity / git SHA /
                                        url+cert SPKI / local path)
       Hasher.Hash(localPath)      → canonical ContentHash + per-file hashes
       Analyzer.Analyze(...)       → []Finding (native matchers, OWASP-mapped)
lockfile.Build(artifacts)          → deterministic snapshot
LockStore.Write + Reporter.Scan
```

**`verify`** — `internal/app/verify`, the rug-pull detector:

```
LockStore.Read                     → locked snapshot
scan.Build (current state)         → current snapshot
lockfile.Compare(locked, current)  → Diff (content/version/integrity/cert/add/remove)
Reporter.Verify + exit code
  --ci also gates on NewFindings(locked, current, threshold)
```

A resolution failure for one artifact never aborts the run: it degrades to a
`RESOLVE-UNSUPPORTED` or `RESOLVE-FAILED` finding so the inventory stays useful.

## Error handling and the CLI contract

- The domain exposes sentinel errors (e.g. `ports.ErrNoLockfile`); services wrap
  with context via `%w`. No panics cross package boundaries.
- Adapters degrade gracefully: a missing Semgrep contributes nothing; an
  unresolved source becomes a finding, not a crash.
- Exit codes are a **stable contract** for CI:

  | Code | Meaning |
  |---|---|
  | `0` | success, no drift |
  | `1` | drift detected, or new findings over threshold (`verify`) |
  | `2` | usage error |
  | `3` | internal / IO error |

- `context.Context` is threaded through the pipeline for cancellation.

## Testing strategy

The hexagon makes each layer testable in isolation:

- **domain** — pure table-driven tests: digest determinism and
  order-independence, `Compare` across every drift kind, severity thresholds.
- **application** — `scan`/`verify` exercised end-to-end against the
  `apptest` fakes, with **no filesystem, network, or subprocess**.
- **adapters** — real behavior against `t.TempDir()` fixtures (native matchers,
  hashing, signing) and a full CLI integration test that scans, verifies, then
  tampers and asserts drift.

Run the whole gate with `make check` (gofmt + vet + tests).

## Extending the system

The seams are deliberate. Common extensions:

- **Add a tool** (Cursor, Codex, Gemini, OpenCode): implement
  `discover.ToolDiscoverer` following `claudecode.go` and add it to
  `discover.Default()`. Nothing else changes.
- **Add a resolver** (npm, git, url): implement `ports.Resolver` and register it
  in `resolve.NewRouter()`. The scan pipeline picks it up automatically.
- **Add analysis** (Semgrep, new native rules): append a rule to
  `analyze.rules`, or add any `ports.Analyzer` to the `analyze.Chain`.
- **Change the signature scheme** (cosign/Sigstore): implement `ports.Signer`
  with a new prefix; callers are unaffected.

## Roadmap seams (Components 2 & 3)

These are documented, not yet built. Each plugs into the same model:

- **`internal/wrap`, `internal/sandbox`, `internal/proxy`, `internal/audit`** —
  the runtime MCP firewall (interposition supervisor + OS sandbox + egress
  proxy with secret redaction). Driven by a future `wrap` command.
- **`internal/client`, `controlplane/`** — the team control plane (policy pull,
  lockfile submission, audit ingest, dashboard).
- **`rules/`, `action/`, `packaging/`** — the Semgrep rules pack, the GitHub CI
  Action, and release tooling (GoReleaser, Homebrew, install.sh, npm shim).

See each directory's `README.md` / `doc.go` for the specific seam.

## Design principles

1. **Keep the core pure.** Integrity logic must be deterministic and testable
   without IO. If it touches the disk or network, it belongs in an adapter.
2. **Depend on interfaces, inward.** Adapters depend on the app; the app depends
   on the domain; the domain depends on nothing.
3. **Degrade, don't crash.** A security tool that breaks a developer's workflow
   gets uninstalled. Unknown or unresolvable inputs become findings.
4. **Determinism everywhere.** Sorted outputs, injected clocks, stable IDs — so
   lockfiles diff cleanly and tests are reproducible.
5. **Minimal dependencies.** The MVP core uses only the Go standard library
   (see [decisions.md](decisions.md)). A supply-chain tool should be auditable
   to the byte.
```
