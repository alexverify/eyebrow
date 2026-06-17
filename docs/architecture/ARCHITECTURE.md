# assay architecture

How the codebase is organized, how a scan actually runs, and where to add code.
Start here if you're contributing. For *why* things are built this way, see
[decisions.md](decisions.md); for what the tool does, see the [README](../../README.md).

## What assay is

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
| `internal/domain/policy` | domain | Team policy model + pure `Evaluate` (the CI gate). |
| `internal/app/ports` | application | All interface definitions + sentinel errors + `Scope`. |
| `internal/app/scan` | application | `scan` use case: discover → resolve → hash → analyze → lock. |
| `internal/app/verify` | application | `verify` use case: recompute → diff → gate. |
| `internal/app/apptest` | application | In-memory fakes implementing every port, for tests. |
| `internal/adapters/discover` | adapter | Per-tool config discovery: Claude Code (MCP, skills, subagents, hooks, context), Cursor (MCP, rules), Gemini (MCP), OpenCode (MCP), Codex (MCP, context). |
| `internal/adapters/parse` | adapter | Config normalizers: JSON, JSONC (hand-rolled), TOML (BurntSushi). |
| `internal/adapters/resolve` | adapter | Source → concrete pinned code: local, inline, npm, git, url. |
| `internal/adapters/hash` | adapter | Filesystem walk feeding the domain digest. |
| `internal/adapters/analyze` | adapter | Native high-signal matchers + optional Semgrep accelerator. |
| `internal/adapters/lockstore` | adapter | Atomic, deterministic `assaylock.json` read/write. |
| `internal/adapters/policystore` | adapter | Loads `assay.policy.json` (optional; defaults if absent). |
| `internal/adapters/sign` | adapter | ed25519 detached signatures. |
| `internal/adapters/report` | adapter | Text and JSON reporters. |
| `internal/cli` | adapter (driving) | Argument parsing, composition root, exit-code mapping. |
| `internal/platform/run` | shared | Command-runner abstraction for shelling out (npm/git), with a fake. |
| `internal/buildinfo` | shared | Build-time version metadata. |
| `cmd/assay` | entrypoint | Thin `main`: signal handling, hand off to the CLI. |

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

## Component 2 — the MCP shim (observe-only slice built)

`assay wrap` routes a tool's stdio MCP servers through
`assay mcp-shim`, which relays JSON-RPC byte-for-byte and audits every
`tools/call`. The slice follows the same hexagon:

- **`internal/domain/jsonrpc`** — pure message classification and the
  request/response tracker correlating each `tools/call` with its outcome.
- **`internal/domain/audit`** — the event model; tool-call arguments are
  recorded only as a content digest, never raw.
- **`internal/app/shim`** — the relay use case: two line pumps over abstract
  readers/writers, inspection on a parsed copy, forwarding untouched. Tested
  entirely with in-memory pipes.
- **`internal/adapters/auditlog`** — JSONL sink, one file per UTC day under
  `~/.assay/audit/`.
- **`internal/adapters/mcpconfig`** — the `.mcp.json` rewrite. The wrapped
  form embeds the original argv after a `--`, so unwrap and `wrap --status`
  are derived from the config itself, no side-channel state. Discovery reuses
  the same recognition (`mcpconfig.UnwrapArgv`) to see through wrapped
  entries — wrapping never reads as drift on verify.
- **`internal/domain/secrets`** — pure credential-shape detection/redaction,
  used by the egress proxy on plain-HTTP bodies.
- **`internal/proxy`** — the per-server egress proxy the shim injects via
  `HTTP(S)_PROXY`: policy host rules (`policy.DecideHost`), body redaction,
  and a `kind:"egress"` audit event per connection (host, method, bytes both
  ways, redactions). CONNECT tunnels are allowlisted and byte-counted but not
  inspected (no TLS interception).

- **`internal/sandbox`** — OS confinement applied by the shim: a pure
  `Profile` (workspace, proxy address, deny paths) and platform backends that
  wrap the server's argv. Seatbelt (`sandbox-exec`) on macOS, bubblewrap on
  Linux, identity fallback elsewhere. Permissive reads minus secret paths,
  writes limited to the workspace + scratch, network limited to the proxy
  port — which makes the egress proxy enforced rather than cooperative.
  Profile generation is pure and unit-tested; confinement itself is verified
  by host-gated integration tests.

## Component 3 — dashboard & team intelligence (built)

`assay dashboard` serves a local, loopback-only web view: a Go `/api/*` backend
and an embedded Next.js export (`controlplane/web` → `internal/dashboard/assets`
via `go:embed`). `internal/dashboard` assembles the UI shape in `BuildScan`
(pure: inventory joined with the locked snapshot, drift class, findings) and
serves it. Every intelligence feature is an IO-free domain package the backend
joins in — same discipline as `Compare` and trust scoring:

- **`internal/domain/trust`, `provenance`, `advisory`, `posture`** — the trust
  verdict + score, the provenance ladder, the known-malicious feed, and the
  counts-only posture trend.
- **`internal/domain/usage`** — folds the audit log into per-artifact
  invocation stats (last/first used, count) and the **dormant-then-active**
  ("sleeper") rule: an old, unused artifact that drifts and then runs.
- **`internal/domain/risk`** — capability × usage fusion: classifies a finding's
  artifact as live / exercised / unknown and ranks exercised risk first.
- **`internal/domain/reach`** — reachability of a finding's file by path
  heuristic (a test/example/vendored path is `inert`, likely noise); demotes,
  never deletes.
- **`internal/domain/timeline`** — the per-artifact event ribbon (installed →
  approved → invoked → drifted), ordered and labeled.
- **`internal/domain/fleet`** — aggregates content-free per-developer snapshots
  into a team **blast-radius**, an artifacts × machines **heatmap**, and a
  **policy-conformance** rollup (`CheckConformance`, reusing
  `policy.ListViolations`).
- **`internal/domain/reputation`** — the opt-in, hash-keyed community trust
  signal; a lookup is a local map lookup, so nothing leaves the machine.
- **`internal/domain/textdiff`** — a dependency-free LCS line differ (with
  hunking) that turns approved vs. current bytes into the literal `+`/`-` lines
  of the rug-pull diff (H1b).

Driven adapters for the above: **`internal/adapters/auditlog`** (read the JSONL
audit log), **`historystore`** (posture trend), **`policystore`** (policy read/
write), **`fleetstore`** (one JSON snapshot per owner under `.assay/fleet/`),
**`repstore`** (the opt-in reputation corpus), **`hookconfig`** (install/
remove the host-tool usage hooks in Claude Code's `settings.json`, idempotently,
the same rewrite discipline as `mcpconfig`), and **`snapshotstore`** (the
content-addressed cache of approved file bytes that feeds the H1b line diff,
captured at scan via the optional `ports.SnapshotSink`). The **`assay fleet`** command
(`internal/cli/fleetcmd.go`) writes this machine's snapshot and prints the
aggregated report; the dashboard reads the same directory.

Usage telemetry has two feeds, both keyed by artifact name and folded by
`internal/domain/usage` (MCP tool calls on the bare name, activations under
`usage.ActivationKey` so same-named kinds never conflate): the MCP shim's
`tool_call` events, and `activation` events written by `assay record-use`
(`internal/cli/recordusecmd.go`) — which a `PreToolUse` hook installed by
`assay install-hooks` (`internal/cli/installhookscmd.go`) calls on every skill
and subagent invocation. This extends usage, the sleeper signal, the
live-finding ranking, and the timeline to non-MCP kinds without any new join.

## Team control plane (self-hostable)

The first slice (4a) is built: a self-hostable team server that ingests
content-free fleet snapshots and serves the aggregated blast-radius, reusing the
exact pure functions the local dashboard uses.

- **`internal/controlplane`** — the server: a `Service` (`Submit`/`Fleet`/
  `Policy`/`TrustedKeys`) over two ports — a mutable `Store` (per-machine
  snapshots) and a read-mostly `Config` (admin-set org policy + trusted keys) —
  an HTTP handler (`POST /v1/snapshots`, `POST /v1/audit`, `POST /v1/reputation`,
  `GET /v1/fleet`, `GET /v1/gate`, `GET /v1/alerts`, `GET /v1/policy`,
  `GET /v1/registry/keys`, `/v1/healthz`), and machine bearer-token auth scoping
  every request to one org.
  `Fleet` is `fleet.Aggregate`, `Gate` is `fleet.Gate`, and `Alerts` is
  `alert.Derive` over the org's snapshots and ingested audit — so the hosted
  report, CI gate, and alerts are byte-identical to the local computation.
- **`internal/domain/alert`** — pure derivation of team alerts (drift,
  quarantine, blocked egress, denied tool calls) from a fleet report + audit
  events; content-free snapshots carry no findings, so it alerts on what it can
  prove and names the gap rather than faking finding-level alerts.
- **`internal/adapters/cpstore`** — the zero-dependency default persistence,
  satisfying both ports: snapshots under `<dir>/<org>/snapshots/<owner>.json`,
  the admin config as `<dir>/<org>/policy.json` and `trustedkeys.json`. A Postgres
  adapter can replace it behind the same interfaces for scale.
- **`internal/client`** — the opt-in CLI client (`Submit`/`Fleet`/`Policy`/
  `TrustedKeys`/`Health`); any error is the caller's signal to fall back to the
  local path, and a 404 on policy means "keep the local policy."
- CLI: `assay serve` runs the server; `assay fleet push` / `assay audit push`
  submit this machine's snapshot and audit events; `assay fleet --server …` reads
  the org report and `assay alerts` its alerts; `verify` pulls the org policy and
  trusted keys (server-preferred, local fallback); `assay fleet verify --server …`
  gates the fleet on the server over submitted snapshots.

The live hash-only reputation lookup (H3b) reuses the existing `reputation.Source`
seam: the dashboard's `Reputation` dep now resolves a corpus for the inventory's
content hashes, served either from a local file or — when a server is configured
— from `POST /v1/reputation`, which returns matches only.

The dashboard on hosted data (4e) keeps the **loopback-only** UI and swaps its
data source: `assay dashboard --server` wires the `Fleet`, `Conformance`,
`Alerts`, and `Reputation` deps to the control-plane client instead of local
stores, with a new `/api/alerts` endpoint. No network UI and no SSO — the machine
token authenticates the CLI's calls; the per-artifact scan view stays local
(hosted snapshots are content-free). What leaves a machine, and only on opt-in,
is specified in [`docs/privacy.md`](../privacy.md). **`packaging/`** — release
tooling beyond GoReleaser — remains a seam, as does a centrally-hosted multi-user
UI with SSO. See each directory's `README.md` / `doc.go`.

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
