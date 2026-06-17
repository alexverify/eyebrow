# Using assay

Two workflows: solo (you, your machine) and team (committed lockfile, policy
gate in CI). Both revolve around the same three files, all committed next to
each other:

| File | What it is | Written by |
|---|---|---|
| `assaylock.json` | The locked inventory: every artifact, hashed and pinned | `assay scan` |
| `assay.policy.json` | What `verify --ci` fails on | you, by hand |
| `assay.trustedkeys` | Whose lockfile signatures count | `assay key trust` |

## Solo: catch rug pulls

```sh
cd your-project
assay scan            # inventory + hash everything → assaylock.json
assay verify          # later: did anything change since I looked?
```

`scan` discovers skills, MCP servers, hooks, subagents, and rules across Claude
Code, Cursor, Gemini, OpenCode, and Codex (add `--global` to include your
user-level setup), pins remote sources (npm version + integrity, git SHA, TLS
cert), hashes content, and runs static analysis. `verify` recomputes all of it
and diffs against the lockfile — exit `1` means something changed underneath
you. `diff` is the same comparison without the failing exit code; `list` is the
inventory without writing anything.

When a change is expected (you updated a skill on purpose), re-run
`assay scan` to re-lock, review the diff in version control, and move on.

## Team: gate CI on "approved, unmodified, signed"

One-time setup, committed to the repo:

```sh
assay scan
assay approve --all --sign           # review first, then bless the inventory (signed)
echo '{ "requireApproval": true, "requireSignature": true }' > assay.policy.json
assay key show                       # each teammate shares this output…
assay key trust <key> --name alice --file assay.trustedkeys   # …and registers the others
assay sign                           # sign the lockfile with your key
git add assaylock.json assay.policy.json assay.trustedkeys
```

CI runs `assay verify --ci` (or the [GitHub Action](../action/README.md)).
The build fails on:

- **drift** — any artifact whose content hash, pinned version, npm integrity,
  or remote TLS cert moved since the lockfile was written;
- **new findings** at/above `failOnSeverity` (default `high`) that weren't in
  the locked snapshot — pre-existing accepted findings don't re-fire;
- **unapproved artifacts**, when `requireApproval` is set — anything added
  without an `assay approve`;
- **unsigned or forged approvals**, when `requireSignedApproval` is set — each
  approval must carry a signature (`assay approve --sign`) from a trusted
  key over the artifact's content, so an approval can't be hand-added to the
  lockfile or kept across a content change;
- **a missing or untrusted signature**, when `requireSignature` is set — the
  lockfile must be signed by a key in `assay.trustedkeys`.

The day-to-day loop: someone adds or updates an extension → `scan`, review,
`approve <id>`, `sign`, commit. Until they do, every other machine's CI is red
with the exact artifact and hash that moved.

False positive from a rule? Suppress it explicitly instead of lowering the
threshold:

```jsonc
{ "ignoreRules": ["EXEC-PRIMITIVE", "SEMGREP-SUBPROCESS-SHELL-TRUE"] }
```

## Key handling

`assay sign` and `key show` use (and create on first use) a persistent
ed25519 key at `~/.assay/key` — per person, per machine; it never leaves
your home directory. Only **public** keys go in `assay.trustedkeys` (one
base64 key per line, optional label, `#` comments). When no registry declares
any key, your own key is implicitly trusted so the solo flow needs no setup;
once a registry exists it is authoritative, locally and in CI alike.

## Deeper analysis with Semgrep (optional)

If `semgrep` is on `PATH` and a rules pack is present (`--rules`, default
`./rules` — see [rules/README.md](../rules/README.md)), scans add
language-aware findings (`SEMGREP-*`) on top of the native matchers. Nothing is
required: no semgrep, no rules dir, or a broken semgrep all degrade to the
native analysis alone.

## Watching your MCP servers (`wrap`)

Static analysis tells you what an MCP server *could* do; the shim records what
it *actually does*:

```sh
assay wrap              # route this project's stdio MCP servers through the shim
assay wrap --global     # same for your user-level ~/.claude.json servers
assay wrap --status     # what's wrapped, and what really runs underneath
assay unwrap            # restore the original config (--global for the user-level one)
```

`wrap` rewrites `.mcp.json` so each stdio server launches via
`assay mcp-shim`, which relays the protocol byte-for-byte (the tool can't
tell the difference) and appends one line per tool call to
`~/.assay/audit/<date>.jsonl`:

```json
{"ts":"…","session":"3f2a…","server":"github","kind":"tool_call","tool":"create_issue","argsDigest":"sha256-…","durationMs":412,"status":"ok"}
```

Arguments are recorded only as a digest — the log never holds raw values, so
it can't leak the secrets that pass through tool calls. Session start, server
exit, and calls the server died without answering are logged too.

Wrapping is invisible to `scan`/`verify`: discovery sees through the shim to
the real underlying server, so wrapping never shows up as drift. Claude Code
projects only for now.

### Blocking calls, not just watching them

Add an `mcp` section to the same committed `assay.policy.json` and the
shim enforces it live:

```jsonc
{
  "mcp": {
    "servers": {
      "github": { "denyTools": ["delete_*"] },          // never, even if allowlisted
      "db":     { "allowTools": ["select", "get_*"] },  // exhaustive: only these
      "*":      { "denyTools": ["execute_raw"] }        // applies to every server
    }
  }
}
```

Patterns are glob-style (`delete_*`); deny always wins over allow; a server
with an `allowTools` list may run *only* those tools; servers without rules
are untouched. A denied call never reaches the server — the shim answers the
agent with a JSON-RPC error naming the rule, and the audit log records
`"status":"denied"` with the matched pattern. A missing policy file means
observe-only; a malformed one refuses to start rather than silently dropping
your rules.

The shim resolves the policy file relative to the server's working directory
(the project root, for Claude Code) — the same committed file `verify --ci`
uses, so one artifact carries both the CI gate and the runtime rules.

### Egress: where servers may connect, and what leaves

The shim also starts a local egress proxy per wrapped server and points the
server's HTTP stack at it (`HTTP_PROXY`/`HTTPS_PROXY`). Three things happen
to outbound traffic:

- **Host rules** — `allowHosts`/`denyHosts` next to the tool rules, same
  semantics (`"db": {"allowHosts": ["api.internal.example"]}`). Blocked
  connections get a 403 and an audit line; the attempt is the signal.
- **Secret redaction** — plain-HTTP request bodies are scanned for known
  credential shapes (AWS keys, Anthropic/OpenAI/GitHub/Slack/Google tokens,
  JWTs, PEM private keys, base58 wallet seeds) and matches are replaced with
  `[REDACTED:<kind>]` before forwarding. The audit records counts and kinds,
  never values.
- **Accounting** — every connection logs `host`, `method`, `bytesUp`,
  `bytesDown` as a `kind:"egress"` event in the same JSONL audit log.

One limitation: HTTPS rides CONNECT tunnels the proxy can't see inside, so
redaction applies to plain HTTP only (host rules and byte accounting apply to
everything). Disable per server with `--no-egress-proxy` if something
misbehaves.

### Sandbox: confinement, so the rules can't be bypassed

On macOS (Seatbelt) and Linux (bubblewrap), `wrap` also runs each server
inside an OS sandbox. This is what turns the egress proxy from *cooperative*
(env vars a server could ignore) into *enforced* — a sandboxed server has no
network path except the proxy port, so it cannot connect out directly even if
it tries. The profile:

- **Reads:** permissive, so the runtime and its libraries load — *except*
  credential dirs (`~/.ssh`, `~/.aws`, `~/.config/solana`, `~/.gnupg`,
  `~/.kube`, `~/.docker/config.json`, `~/.npmrc`), which are blocked.
- **Writes:** only the workspace (the project root, or `--workspace <dir>`)
  and scratch/temp dirs. A write anywhere else is denied.
- **Network:** only the local egress proxy port.

Where no sandbox backend is available (other OSes, or `sandbox-exec`/`bwrap`
missing) it degrades to the cooperative behavior rather than failing. Disable
with `--no-sandbox`. Note that servers whose code lives outside the workspace
and the standard system paths may need their location made writable/readable;
start with `--workspace` pointed at a dir that contains what the server needs
to write.

### Reading the audit log

`assay audit` queries what the shim recorded:

```sh
assay audit                          # summary: counts by server, denials, redactions
assay audit --list                   # every event, newest filters applied
assay audit --status denied --list   # just what got blocked
assay audit --server github --since 2026-06-01 --list
assay audit --list --json            # machine-readable
```

Filters (`--server`, `--tool`, `--status`, `--kind`, `--since`) compose. The
summary is the fast "what have my MCP servers been doing" view; `--list` is the
forensic detail.

### Usage telemetry for skills and subagents (`install-hooks`)

The shim gives MCP servers a usage signal for free. Skills, subagents, and the
other artifact kinds have no shim, so they get one from a host-tool hook:

```sh
assay install-hooks                  # add the hooks to ~/.claude/settings.json
assay install-hooks --status         # show what's installed
assay install-hooks --uninstall      # remove them
```

This writes a `PreToolUse` hook on Claude Code's **Skill** and **Task** tools
that calls `assay record-use` on every activation, appending an `activation`
event to the same audit log the shim writes. With it in place, the dashboard's
last/first-used, dormant-then-active sleeper, live-finding ranking, and timeline
light up for skills and subagents too — not just wrapped MCP servers.

It is strictly opt-in and additive: install nothing and those artifacts simply
show "no usage signal" (never a false "unused"). The hook never breaks your
tool — a missing field or any error degrades to a no-op. And like the shim, an
activation records only *that* an artifact ran and when, never its arguments.

`assay record-use` is the command the hook invokes; you rarely run it by hand:

```sh
assay record-use --kind skill --name pdf-skill    # record one activation
echo "$HOOK_JSON" | assay record-use --kind skill --stdin   # extract name from a hook payload
```

## Dashboard

`assay dashboard` serves a local, read-only web view of what assay
sees on this machine — the live inventory, drift against the committed
lockfile, findings, and the MCP shim's audit timeline:

```sh
assay dashboard                 # http://127.0.0.1:7113
assay dashboard --addr 127.0.0.1:9000 --path . --audit-dir ~/.assay/audit
assay dashboard --fleet-dir .assay/fleet --reputation assay.reputation.json
```

It binds loopback only and rejects any request whose `Host` header isn't a
loopback name (defeating DNS-rebinding from a page in your browser); there is
no auth because there is no remotely reachable surface. The UI is a Next.js app
(`controlplane/web`) static-exported and **embedded in the binary** — nothing
to install, works offline. Rebuild it with `make dashboard-web && make build`.

Click any artifact in the inventory to open its **security profile**:

- **Trust verdict** — trusted / review / quarantine with a hand-recomputable
  score breakdown, plus an opt-in **community reputation** line ("trusted by N
  other assay users") when the artifact's exact hash is in your reputation
  corpus (see below).
- **Provenance** — source, launch command, env *keys* only (values are never
  shown), and a provenance ladder.
- **Integrity** — on-disk vs locked hash, signature/approval state verified
  against your trusted keys, and — on a drift — a **changed-files** view naming
  exactly which files moved. When `assay scan` has captured the approved bytes
  (a local, gitignored `.assay/snapshots` cache), each changed file expands to
  its literal **line-level diff** — the actual `+`/`-` lines, the rug-pull made
  visible. Without a captured baseline it degrades to the content-free file-name
  list. Binary and oversized files always stay at the name level.
- **Timeline** — the per-artifact event ribbon: installed → approved → invoked
  → drifted, in time order.
- **Usage** — when it last/first ran and how many times: from the shim's audit
  log for wrapped MCP servers, and from activation hooks for skills and
  subagents (see `install-hooks` above). A **dormant-then-active** banner fires
  when an old, unused artifact drifts and then runs for the first time.
- **Capabilities** — declared exec/network/filesystem, with the diff against the
  locked version (capability expansion is flagged).
- **Findings** — security findings, each badged by **liveness** (a finding on
  code that actually ran outranks one on dormant code) and **reachability** (a
  finding in a test/example/vendored path is marked `inert` and demoted as
  likely noise — never hidden).

The **Activity** tab shows the raw runtime audit timeline for wrapped MCP
servers; the **Fleet** tab is described next.

## Fleet: who is exposed (team blast-radius)

The dashboard above renders one machine. For a team, the question is *who has
what, and where the blast radius is* the moment an advisory lands. assay answers
it the offline-first way — by aggregating **committed snapshots**, not by
uploading live telemetry.

Each developer exports a snapshot and commits it; the dashboard (or the CLI)
aggregates whatever it finds:

```sh
assay fleet export                 # write .assay/fleet/<hostname>.json
assay fleet export --owner alice   # or label it yourself
git add .assay/fleet && git commit # "git is the backend" — same as approvals
assay fleet                        # blast-radius + policy conformance, as text
assay fleet verify                 # CI gate: exit 1 if any machine is out of policy
```

A snapshot is **content-free** — only each artifact's id, name, kind, content
hash, source ref, and the owner's local drift/verdict. No code, no secrets, no
file contents — safe to commit and share. A re-export replaces the owner's prior
snapshot, so the view always reflects the current fleet.

The dashboard's **Fleet** tab turns the aggregated snapshots into three views:

- **Blast radius** — "`crypto-price-feed` drifted — 3 of 8 machines have it,"
  ranked so drifted/quarantined artifacts surface first, with a *variants* count
  (distinct hashes across the fleet — a monoculture vs. a mid-fleet rug-pull).
- **Inventory heatmap** — an artifacts × machines matrix colored by drift/
  verdict, flagging **monoculture** (everyone runs the same thing) and
  **outliers** (one machine has an extension nobody else does).
- **Policy conformance** — every machine evaluated against the committed
  `assay.policy.json`: who is running blocked publishers, unapproved, or
  quarantined artifacts. It turns the policy from advisory into a measured
  "N of M machines in policy."

`assay fleet verify` is the same conformance rollup as an **enforced CI gate**:
it exits `1` (the stable drift/policy code) when any machine is out of policy, or
when a drifted/quarantined artifact's reach exceeds the committed threshold:

```jsonc
// assay.policy.json
{ "fleet": { "maxBlastRadius": 2 } }  // fail if a drift/quarantine spans >2 machines
```

Run it in the same CI job that already commits snapshots, after a step that
collects each machine's `fleet export`. It reuses the exact pure functions the
dashboard renders, so a CI failure matches what a teammate sees in `assay fleet`.
With no `fleet` block in the policy, only machine conformance gates (the reach
check is off). An empty fleet directory is nothing to gate — exit `0`.

The reputation signal (`--reputation <file>`, default `assay.reputation.json`)
is **opt-in and hash-only**: a content-hash → trust-count corpus you choose to
trust. A lookup is a local map lookup, so no hash ever leaves your machine; an
absent corpus is a silent no-op and a miss is "unknown," never a negative claim.

### Hosted control plane (opt-in, beyond ~15 people)

"Git is the backend" caps cleanly at a small team sharing a repo. Past that, run
the self-hostable control plane: it ingests the same content-free snapshots over
HTTP and serves the same aggregated blast-radius. Everything stays optional — the
CLI works fully offline, and a client error falls back to the local path.

```sh
# on the server (a machine your team can reach)
echo '{"sek-alice":"acme","sek-bob":"acme"}' > tokens.json   # machine token → org
assay serve --addr 0.0.0.0:7140 --tokens tokens.json         # file-backed store under ~/.assay/controlplane

# on each developer's machine (or in CI)
export ASSAY_SERVER=https://assay.acme.internal:7140
export ASSAY_TOKEN=sek-alice
assay fleet push            # submit this machine's snapshot
assay fleet --server "$ASSAY_SERVER" --token "$ASSAY_TOKEN"   # read the org blast-radius
```

A bearer token scopes every request to one org (row-level isolation). The
snapshot is content-free, exactly what `fleet export` would commit — ids, hashes,
and drift/verdict, never code or secrets. The default store is the zero-dependency
file backend (one JSON per machine); a Postgres adapter for scale slots in behind
the same interface.

**Org policy and trusted keys (pull).** An admin sets the org's policy and
trusted signing keys on the server (drop `policy.json` / `trustedkeys.json` under
`<store>/<org>/`). The CLI then pulls them, preferring the server over local
files and **falling back to local** if the server has none or is unreachable:

```sh
# single-machine verify pulls the org policy + trusted keys when a server is set
assay verify --ci --server "$ASSAY_SERVER" --token "$ASSAY_TOKEN"
```

A server with no policy for the org returns 404, which the CLI treats as "use the
local `assay.policy.json`" — so adopting a server never silently changes a gate
you didn't configure.

**Hosted CI gate.** With a server set, `assay fleet verify` gates the fleet that
machines have **pushed to the server** — the server runs `fleet.Gate` over the
submitted snapshots and the org policy, so CI needs no local snapshot directory:

```sh
assay fleet push                                              # each machine, e.g. from its own CI
assay fleet verify --server "$ASSAY_SERVER" --token "$ASSAY_TOKEN"   # one CI job gates the whole fleet → exit 1 on breach
```

Without a server, `fleet verify` still gates the local `.assay/fleet` directory.
Either way the gate is the same pure `fleet.Gate`, so a CI failure matches what a
teammate sees in `assay fleet`.

**Audit ingest and team alerts.** Each machine can upload its runtime audit log,
and anyone can read the org's derived alerts:

```sh
assay audit push --server "$ASSAY_SERVER" --token "$ASSAY_TOKEN"   # upload this machine's events
assay alerts     --server "$ASSAY_SERVER" --token "$ASSAY_TOKEN"   # drift / quarantine / blocked egress / denied tools
```

Alerts are derived server-side from the aggregated fleet (drifted or quarantined
artifacts, and on how many machines) and the ingested audit (blocked egress
hosts, denied tool calls). The audit events are **content-free** — tool/server
names, egress hostnames, timings, statuses, and argument *digests*, never raw
arguments or secrets. `audit push` reveals which tools ran and which hosts they
reached, so it is strictly opt-in; see **[docs/privacy.md](privacy.md)** for the
full contract of what leaves a machine. A hosted dashboard and live reputation
lookup are the remaining (designed) slices.

## Exit codes (stable contract)

`0` clean · `1` drift or policy violation · `2` usage error · `3` internal
error. Everything CI needs is in the exit code; `--json` gives machines the
details.

## Platforms

`scan`/`verify`/`sign` and the rest of the inventory side run on Linux, macOS,
and Windows. `wrap`'s OS sandbox exists on macOS (Seatbelt) and Linux
(bubblewrap) only; on **Windows there is no sandbox**, so `wrap` runs servers
unconfined and the egress proxy is cooperative (a server could bypass it) —
tool-policy enforcement and auditing still apply, and `wrap` prints a warning
to make the gap explicit.

**Line endings (cross-OS lockfiles).** assay hashes file bytes exactly as
they are on disk, so if Git rewrites text files to CRLF on Windows checkout, a
text artifact hashes differently than on Linux/macOS and `verify` reports false
drift. If you commit a lockfile that a mixed-OS team verifies, normalize line
endings — commit a `.gitattributes` with `* text=auto eol=lf` (what this repo
does), or set `core.autocrlf=false` for the scanned trees.
