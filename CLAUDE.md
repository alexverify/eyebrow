# eyebrow — project guide for Claude

Supply-chain integrity for AI coding tools: a single static Go binary that
discovers every skill, MCP server, plugin, hook, and rule installed across AI
coding tools, hashes them into a committable lockfile, statically analyzes them,
detects post-audit modification ("rug pulls"), and at runtime can interpose,
sandbox, and audit MCP servers. Repo: `github.com/alexverify/eyebrow`.

## Architecture

Pragmatic **hexagonal (ports & adapters)**, dependencies pointing inward:
`cmd → internal/cli → internal/adapters → internal/app → internal/domain`.

- `internal/domain/*` — pure, IO-free core: `digest` (canonical Merkle hashing),
  `artifact`, `finding`, `lockfile` (Build/Compare/drift), `policy`,
  `jsonrpc`, `audit`, `secrets`.
- `internal/app/*` — use cases on `ports` interfaces only: `scan`, `verify`,
  `shim` (the MCP relay), plus `apptest` in-memory fakes.
- `internal/adapters/*` — concrete IO: `discover` (per-tool), `parse`,
  `resolve` (npm/git/url), `hash`, `analyze` (native + semgrep), `lockstore`,
  `policystore`, `sign` (ed25519 + keyring), `auditlog`.
- `internal/proxy`, `internal/sandbox` — Component 2 runtime pieces.
- `internal/dashboard` — Go backend + embedded Next.js UI.
- `controlplane/web` — the Next.js dashboard source.

**Zero external dependencies is a design principle** (auditable supply-chain
tool). Deliberate exceptions, each justified in `docs/architecture/decisions.md`:
`github.com/BurntSushi/toml` (Codex configs). The dashboard frontend has its own
npm deps but they are build-time only — the binary embeds the static export.

## Conventions (follow these)

- **TDD**: failing test → implement → pass. `make check` (gofmt + vet + tests)
  is the gate; run it before every commit.
- **Commits**: short, subject-line-only, no AI-sounding body, and **never** a
  `Co-Authored-By: Claude` trailer. (User preference — non-negotiable.)
- **Exit codes** (stable CLI contract): `0` clean · `1` drift/policy violation ·
  `2` usage · `3` internal error.
- Adapters are added behind one interface; discovery tools are a one-line change
  to `discover.Default()`.

## Build & dev

```sh
make build          # → ./bin/eyebrow (CGO_ENABLED=0, version stamped)
make check          # gofmt + vet + tests — the local CI gate
make dashboard-web  # npm ci && next build, sync export → internal/dashboard/assets
```

CI: `.github/workflows/ci.yml` runs `make check` + `make build` on Linux/macOS/
Windows (actions pinned by SHA, `shell: bash` for the Windows runner).
`dashboard.yml` builds the Next.js app + `npm audit` on `controlplane/web`
changes. Releases via GoReleaser on `v*` tags (darwin/linux/windows, amd64/arm64).

## Status

- **Component 1** (scan/verify/lockfile/sign) — complete. Tools: Claude Code,
  Cursor, Gemini, OpenCode, Codex, Windsurf, Copilot CLI. Linux/macOS/Windows.
- **Component 2** (runtime MCP firewall) — complete: `wrap`/`unwrap` rewrite
  `.mcp.json` to route stdio servers through `eyebrow mcp-shim`, which relays
  JSON-RPC byte-for-byte, enforces per-server tool policy (deny → JSON-RPC error),
  injects a redacting egress proxy, and confines via OS sandbox. Audit log at
  `~/.eyebrow/audit/<date>.jsonl`; query with `eyebrow audit`.
- **Component 3** — local **dashboard** shipped (`eyebrow dashboard`, loopback,
  embedded Next.js UI on live data via `/api/scan`, with a per-artifact detail
  drawer). Hosted team control plane (Postgres/multi-tenant API) still designed.

## Hard-won gotchas (don't relearn these)

- **`.gitignore` patterns must be root-anchored** (`/eyebrow`, not
  `eyebrow`) or they hide directories like `cmd/eyebrow/`.
- **CRLF**: a `.gitattributes` forces `* text=auto eol=lf`. Required so gofmt
  passes on Windows AND so content hashes are stable cross-OS (a CRLF flip
  reads as drift).
- **Windows**: `os.UserHomeDir` reads `USERPROFILE`, not `HOME` (tests must set
  both). Process termination uses `Kill`, not `SIGTERM`. Git Bash's MSYS layer
  mangles env-var *values* containing `://` (e.g. `HTTP_PROXY`) — a test-harness
  quirk, not a product bug; real native servers get the env intact.
- **Sandbox (Seatbelt/bwrap)**: match **symlink-resolved** paths — `/tmp` and
  `/var` are symlinks into `/private` on macOS, so `EvalSymlinks` before
  emitting profile paths. Seatbelt network rules need host `localhost`/`*`, not
  a literal IP. Reads are permissive (a too-tight read profile SIGABRTs the
  interpreter); writes + network are locked down. Sandbox is Unix-only — `wrap`
  warns when unconfined (e.g. Windows).
- **Signing stability**: anything volatile must stay out of the lockfile's
  canonical bytes. `artifact.ModifiedAt` (file mtime, for the dashboard) is
  `json:"-"` for exactly this reason — persisting it would churn the lockfile
  and break signatures.
- **Audit log never stores raw values**: tool-call args and secrets are
  digested/redacted; the dashboard exposes env **keys only**, never values.
- **Dashboard npm audit**: keep it at 0 vulns (a supply-chain tool can't ship a
  vulnerable dep). The transitive `postcss` advisory is pinned via a
  `"postcss": "$postcss"` override + a direct `^8.5.10` devDependency.

## Dashboard specifics

Hybrid: Next.js frontend (`controlplane/web`, static-exported via
`output: 'export'`) embedded in the Go binary with `go:embed`; the backend is
Go `/api/*` (`/api/scan` assembles the UI shape — inventory joined with the
locked snapshot, drift status, kind/agent mapping, finding pattern/title maps).
The built export under `internal/dashboard/assets` is committed (the shipped
artifact); `node_modules`/`.next`/`out` are gitignored. Loopback-only with a
`Host`-header guard against DNS rebinding; no auth (no remote surface). After UI
changes: `make dashboard-web && make build`.

## Docs

`docs/architecture/ARCHITECTURE.md` (package map, data flow, extension points),
`docs/architecture/decisions.md` (key trade-offs), `docs/usage.md` (solo + team
workflows, wrap/audit/dashboard).
