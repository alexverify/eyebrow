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

## Fleet is aggregated snapshots, not live telemetry

The team blast-radius (`internal/domain/fleet`) is built the same offline-first
way as approvals: each developer's `assay fleet export` writes a **content-free**
snapshot — artifact id, name, kind, content hash, source ref, and the owner's
local drift/verdict, *nothing else* — under `.assay/fleet/`, which is committed
to the repo. The dashboard aggregates whatever snapshots it finds. No server, no
telemetry upload, no secrets, no code leaves a machine. "Git is the backend,"
the same principle as the lockfile and the trusted-keys registry. A hosted API
could replace the directory later without changing the aggregation, which is
pure (`fleet.Aggregate` / `fleet.CheckConformance`).

## Line-level drift diffs live outside the signed lockfile

The file-manifest diff (H1) names *which* files changed using only per-file
hashes — content-free, and part of the signed lockfile. Showing the *literal*
changed lines (H1b, the `+ fetch("https://collect…")` an auditor wants) needs
the bytes, and bytes must not go in the lockfile: they would bloat the
committed file and, worse, churn the canonical signing bytes on every edit.

So the approved bytes live in a separate, content-addressed blob store
(`internal/adapters/snapshotstore`, default `<project>/.assay/snapshots`,
gitignored) — a *local cache of baselines*, explicitly not part of the integrity
anchor. `assay scan` (and the dashboard's live build) capture each artifact's
files keyed by content hash; because it is content-addressed, the same hash is
captured once. The dashboard then diffs the locked hash's bytes against the
current hash's bytes with the pure `internal/domain/textdiff` LCS differ.

Three deliberate limits keep it honest and bounded: binary and oversized
(>256 KB) files are skipped at capture, so the diff degrades to the file-name
list for them; a hash never re-captured (e.g. a baseline predating the feature)
also degrades to the name list — the diff is an *enhancement, never a
requirement*; and the store is project-local and gitignored, never shared, so it
is a cache a teammate or CI rebuilds, not a committed artifact. `textdiff` is a
hand-rolled LCS for the same reason the rest of the core is dependency-free —
but a *bounded* line differ, not a parser, so the correctness bar that justified
the TOML dependency does not apply here.

## The hosted dashboard stays loopback-only, not a network UI

The team dashboard on hosted data (4e) keeps the existing **loopback-only** UI
and only swaps its data source: `assay dashboard --server` points the `Fleet`,
`Conformance`, `Alerts`, and `Reputation` deps at the control-plane client. We
deliberately did *not* serve the UI over the network with an SSO login. The
reason is the dashboard's founding constraint — "no auth because there is no
remotely reachable surface." A network-served UI would reintroduce exactly that
surface (and an OIDC dependency) for a tool whose whole pitch is a small,
auditable attack surface. Keeping the UI on loopback means the machine bearer
token authenticates only the CLI→server calls, there is no session/cookie/redirect
machinery, and the whole thing is testable headlessly.

The honest cost: the per-artifact security profile (findings, capabilities, line
diffs) stays **local**, because hosted snapshots are content-free by design — so
that view reflects this machine while Fleet and Alerts reflect the team. A
centrally-hosted multi-user UI with SSO is a real product (multi-user sessions,
an identity provider, a published web attack-surface review); it is left as a
future extension rather than bolted on here.

## The control plane is a self-hostable binary that reuses the pure core

The team server (`internal/controlplane`, slice 4a) is a *self-hostable single
binary* (`assay serve`), not a managed SaaS. That matches the run-it-yourself,
auditable ethos and defers the hardest SaaS concerns (billing, residency, our
own breach surface); a multi-tenant SaaS later is the same binary with tenancy
on by default. It is written in Go specifically so the server's `Fleet` endpoint
is literally `fleet.Aggregate` over the org's snapshots — the hosted report is
byte-identical to the local one, and there is no second language/dependency tree
to audit.

Two deliberate choices keep it honest. **Persistence defaults to a
zero-dependency file store** (`internal/adapters/cpstore`, one JSON per machine)
in the same "files are the backend" spirit as the rest of assay; Postgres is a
future adapter behind the same `Store` port, for scale, not a baseline
requirement — so `serve` adds no dependency to the shipped binary. **Auth is a
machine bearer token scoping each request to one org** (constant-time compare,
row-level isolation); OIDC for humans and admin token management come with the
web slice. The whole thing is opt-in and additive: the CLI never requires a
server, the submitted snapshot is content-free (the same bytes `fleet export`
commits), and any client error falls back to the local path — the advisory-feed
contract, now over HTTP.

## Org policy and keys are admin config, pulled with a local fallback

The control plane separates two kinds of state behind two ports: a mutable
`Store` (each machine's fleet snapshot, written by that machine) and a
read-mostly `Config` (the org policy and trusted keys, set by an admin). They are
distinct because they have different owners and lifecycles — conflating them
would let a machine's submission touch the team's policy. The file backend keeps
snapshots in a `snapshots/` subdir precisely so an owner literally named
"policy" can't collide with `policy.json`.

The CLI **prefers the server but falls back to local**: `verify` and
`fleet verify` pull `GET /v1/policy` and `GET /v1/registry/keys` when a
`--server` is set, but a 404 (no org policy) or any transport error drops back to
the committed `assay.policy.json` / trusted-keys registry. So adopting a server
never silently changes a gate you didn't configure, and an unreachable server
never blocks CI — the same advisory-feed contract the offline reputation and
advisory feeds follow. The server policy is `Normalize`d exactly as
`policystore.Load` normalizes the local one, so the two paths gate identically.

## The fleet CI gate reuses the dashboard's pure rollups

`assay fleet verify` enforces what the dashboard's Fleet tab shows. Rather than
re-deriving compliance, `fleet.Gate` is a thin pure function over the
already-computed `Aggregate` (blast radius) and `CheckConformance` (per-machine
policy) results — the exact values the dashboard renders. So a CI failure can
never disagree with what a teammate sees locally. It fails on two conditions:
any machine out of policy, and a drifted/quarantined artifact whose reach
exceeds a committed `fleet.maxBlastRadius` (zero = reach check off, conformance
alone gates). The threshold lives in `assay.policy.json`, reviewed like every
other rule, and the gate exits `1` — the same stable drift/policy code as
`verify --ci`, so existing CI consumers need no new exit-code handling. An empty
fleet directory is nothing to gate (exit `0`), keeping the gate safe to add
before any snapshots exist.

## Reputation is a local, hash-only, opt-in corpus

The community trust signal (`internal/domain/reputation`) is keyed solely by
content hash — no identity, no code, no source. Privacy is **structural, not
promised**: the corpus is data the user already holds, so a lookup
(`Source.Lookup`) is a local map lookup that sends nothing. It is strictly
opt-in (an absent corpus is a silent no-op, like the advisory feed offline) and
a miss is "unknown," never a negative claim.

The live hash-only lookup (H3b) is now built behind that same `reputation.Source`
seam: an admin hosts the org's corpus on the control plane, and the dashboard's
`Reputation` dep resolves the inventory's hashes from `POST /v1/reputation`
instead of a local file. Privacy stays structural — the lookup sends only the
content hashes the caller already holds (a hash discloses nothing about content
you don't), and the server returns **matches only**, never the whole corpus. It
is an org-scoped corpus (the team's curated "we trust this exact hash" set), not
a global community service; a cross-org community endpoint is a further extension
behind the same seam.

## Reachability is a location heuristic, not a call graph

A finding in a test fixture, an example script, or a vendored dependency almost
never runs in production, so it is noise. A zero-dependency static binary cannot
trace imports across every ecosystem, so `internal/domain/reach` classifies a
finding's file by **path** (a `test/` `examples/` `vendor/` `node_modules/`
segment, or a `_test.go` / `.test.` / `.spec.` name → `inert`) and the dashboard
**demotes** inert findings — sorts them last, badges them — but **never hides**
them. Same discipline as the H1 file-diff: name what you can prove, claim
nothing you cannot. A future call-graph pass could upgrade the seam to true
reachability without changing the surface.

## Usage telemetry: tool calls for MCP servers, activations for everything else

Per-artifact usage (`internal/domain/usage`) and the live/exercised finding
ranking (`internal/domain/risk`) are derived from the audit log. Two event
sources feed it, both keyed by **artifact name**:

- **MCP servers** — the shim records a `tool_call` for each invocation, keyed by
  the server name. This is the original join (no setup needed once a server is
  wrapped).
- **Everything else** — skills, subagents, plugins, hooks have no shim, so
  `assay install-hooks` writes a host-tool `PreToolUse` hook (Claude Code's
  Skill and Task tools) that shells out to `assay record-use`, appending an
  `activation` event. This lights up the same first/last-used, sleeper (F2),
  live-finding (F3), and timeline (F4) signals for non-MCP kinds.

The two sources live in **separate namespaces** in the summarized map — MCP on
the bare name, activations under `usage.ActivationKey` — so a skill and an MCP
server that happen to share a name never conflate their telemetry. An artifact
with neither kind of event is shown honestly as "no usage signal," never
inferred as "unused." Activations record only *that* an artifact ran and when
— never arguments (those routinely hold secrets), the same redaction discipline
as the shim. An artifact that the user never installs the hooks for stays a
silent no-op: telemetry is opt-in and additive, never a precondition for the
scan view.
