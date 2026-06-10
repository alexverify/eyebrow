# agentguard — initial architecture design

- Date: 2026-06-10
- Status: Approved; Component 1 scaffolded and implemented
- Source idea: MVP Technical Build Spec — "Agent Skill/MCP Supply-Chain
  Integrity & Runtime Firewall"

## 1. Product, in one sentence

A single static binary that (a) discovers every skill / MCP server / plugin /
hook installed across a developer's AI coding tools, hashes them into a
lockfile, statically scans them, and detects post-audit modification ("rug
pulls"); and (b) — later — runs MCP servers inside an OS sandbox behind an
egress proxy enforcing a domain allowlist and secret redaction; with (c) — later
— a control plane for team policy, a signature registry, audit logs, and a CI
gate.

The product splits into three deliverables shipped in order:

1. **`scan` + `verify` + lockfile** — the wedge; read-only, no privileges.
2. **`wrap`** — runtime MCP gateway + sandbox + egress proxy (the moat).
3. **Control plane** — policy API, signature registry, audit log, CI Action,
   dashboard (the revenue layer).

**This design covers the architecture for the whole product and the full
implementation of Component 1.** Components 2 and 3 exist as documented seams.

## 2. Decisions

These were settled before implementation:

| Decision | Choice | Rationale |
|---|---|---|
| Scope of this pass | Full repo skeleton + Component 1 fully built | The wedge has standalone value and is the distribution engine; the rest are clean seams to avoid premature abstraction. |
| Architecture style | Pragmatic hexagonal (ports & adapters) | Pure, testable core; swappable edges; idiomatic and approachable. See [ADR-0001](../../architecture/adr/0001-hexagonal-architecture.md). |
| Deliverable | Buildable skeleton + docs | `go build`/`go test` green from commit one; a working CLI to grow from. |
| Module path | `github.com/alexverify/agentguard` | Dedicated org namespace for a multi-repo product. |
| License | Apache-2.0 | Permissive with patent grant; the norm for security/infra tooling. |
| Dependencies | Standard library only (MVP) | A supply-chain tool should be auditable to the byte. See [ADR-0002](../../architecture/adr/0002-standard-library-only.md). |
| Static analysis | Native matchers first; Semgrep optional | Zero-dependency analysis that still works; Semgrep accelerates when present. See [ADR-0003](../../architecture/adr/0003-semgrep-optional-accelerator.md). |
| Signing | ed25519 now; cosign later behind the same port | Ships without dependencies; upgradeable. See [ADR-0004](../../architecture/adr/0004-ed25519-signing.md). |

## 3. Architecture overview

Three concentric layers with dependencies pointing inward: **domain** (pure
core) ← **application** (use cases + ports) ← **adapters** (CLI + driven
adapters). Full detail, the package map, data-flow diagrams, error/exit-code
contract, testing strategy, and extension points are in
[docs/architecture/ARCHITECTURE.md](../../architecture/ARCHITECTURE.md).

Key architectural decision carried from the build spec: **the MCP unit, not the
whole agent, is what Component 2 will sandbox.** Each MCP server is already a
separate process; interposing a supervisor yields isolation, inspection,
redaction, and audit without modifying the agent.

## 4. The integrity primitives (domain)

- **Canonical digest** (`domain/digest`): a Merkle-style root over
  POSIX-sorted per-file SHA-256 hashes —
  `sha256( Σ path‖0x00‖sha256(bytes)‖0x00 )` — independent of walk order, so the
  same bytes always produce the same `sha256-…` digest.
- **Lockfile diff** (`domain/lockfile`): `Compare(locked, current)` classifies
  every change as added / removed / content_changed / version_changed /
  integrity_changed / cert_rotated. This is the rug-pull detector.
- **Integrity anchors by source kind**: npm → `pkg@version` + npm integrity;
  git → commit SHA; url → URL + TLS SPKI pin; local → content hash; inline →
  literal content hash.

## 5. Implemented vs. stubbed

**Fully implemented (Component 1 wedge):**

- Pure domain: `artifact`, `finding`, `digest`, `lockfile` (with full unit
  tests for the digest and diff algorithms).
- Use cases: `scan` and `verify`, tested end-to-end with in-memory fakes.
- Adapters: Claude Code discovery (`.mcp.json` + skills), local/inline
  resolution, filesystem hashing, native OWASP-mapped matchers, atomic
  lockfile store, ed25519 signing, text/JSON reporters.
- CLI: `scan`, `verify` (+ `--ci`), `diff`, `list`, `approve`, `version`, with a
  stable exit-code contract, exercised by an integration test that detects a
  simulated rug pull.

**Documented seams (not yet built):**

- Resolvers for npm / git / remote-url (return `ErrNotImplemented`; scan
  degrades to a finding).
- Tolerant JSONC and TOML parsers.
- Discoverers for Cursor, Codex, Gemini, OpenCode.
- Semgrep invocation + result mapping.
- Component 2: `internal/wrap`, `internal/sandbox`, `internal/proxy`,
  `internal/audit`.
- Component 3: `internal/client`, `controlplane/`.
- Distribution: `rules/`, `action/`, `packaging/`.

## 6. Build order (by dependency, from the spec)

1. discover + parse + list — read-only inventory. ✅ (Claude Code)
2. resolve + hash + lockfile + scan/verify/diff — the wedge. ✅ (local/inline;
   npm/git/url seamed)
3. analyze native matchers, then Semgrep + OWASP mapping. ✅ native; Semgrep
   seamed.
4. sign (ed25519) + approve workflow. ✅
5. wrap: MCP shim + supervisor → sandbox → proxy + redaction. ▢ seamed.
6. control plane: policy pull + lockfile submit + dashboard → audit ingest. ▢
   seamed.
7. CI Action. ▢ seamed.

## 7. Acceptance for this pass

- `make check` (gofmt + vet + tests) passes.
- `agentguard scan` on a real project produces a deterministic `agentlock.json`,
  flags high-signal patterns, and degrades gracefully on unresolvable sources.
- `agentguard verify` detects content drift (rug pull) and returns a non-zero
  exit code; `--ci` additionally gates on new high/critical findings.
- Architecture and decisions are documented (this spec, ARCHITECTURE.md, ADRs).

## 8. Honest limitations (carried from the spec)

- Remote MCP code cannot be hashed; cert pinning + allowlists are the ceiling.
- Bare-interpreter commands (e.g. `node script.js`) are not yet resolved to the
  script's bytes; they currently degrade to a finding.
- Config paths drift between tool versions; discovery is deliberately tolerant
  and tool coverage grows behind the `ToolDiscoverer` seam.
```
