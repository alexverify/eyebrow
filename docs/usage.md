# Using agentguard

Two workflows: solo (you, your machine) and team (committed lockfile, policy
gate in CI). Both revolve around the same three files, all committed next to
each other:

| File | What it is | Written by |
|---|---|---|
| `agentlock.json` | The locked inventory: every artifact, hashed and pinned | `agentguard scan` |
| `agentguard.policy.json` | What `verify --ci` fails on | you, by hand |
| `agentguard.trustedkeys` | Whose lockfile signatures count | `agentguard key trust` |

## Solo: catch rug pulls

```sh
cd your-project
agentguard scan            # inventory + hash everything → agentlock.json
agentguard verify          # later: did anything change since I looked?
```

`scan` discovers skills, MCP servers, hooks, subagents, and rules across Claude
Code, Cursor, Gemini, OpenCode, and Codex (add `--global` to include your
user-level setup), pins remote sources (npm version + integrity, git SHA, TLS
cert), hashes content, and runs static analysis. `verify` recomputes all of it
and diffs against the lockfile — exit `1` means something changed underneath
you. `diff` is the same comparison without the failing exit code; `list` is the
inventory without writing anything.

When a change is expected (you updated a skill on purpose), re-run
`agentguard scan` to re-lock, review the diff in version control, and move on.

## Team: gate CI on "approved, unmodified, signed"

One-time setup, committed to the repo:

```sh
agentguard scan
agentguard approve --all                  # review first, then bless the inventory
echo '{ "requireApproval": true, "requireSignature": true }' > agentguard.policy.json
agentguard key show                       # each teammate shares this output…
agentguard key trust <key> --name alice --file agentguard.trustedkeys   # …and registers the others
agentguard sign                           # sign the lockfile with your key
git add agentlock.json agentguard.policy.json agentguard.trustedkeys
```

CI runs `agentguard verify --ci` (or the [GitHub Action](../action/README.md)).
The build fails on:

- **drift** — any artifact whose content hash, pinned version, npm integrity,
  or remote TLS cert moved since the lockfile was written;
- **new findings** at/above `failOnSeverity` (default `high`) that weren't in
  the locked snapshot — pre-existing accepted findings don't re-fire;
- **unapproved artifacts**, when `requireApproval` is set — anything added
  without an `agentguard approve`;
- **a missing or untrusted signature**, when `requireSignature` is set — the
  lockfile must be signed by a key in `agentguard.trustedkeys`.

The day-to-day loop: someone adds or updates an extension → `scan`, review,
`approve <id>`, `sign`, commit. Until they do, every other machine's CI is red
with the exact artifact and hash that moved.

False positive from a rule? Suppress it explicitly instead of lowering the
threshold:

```jsonc
{ "ignoreRules": ["EXEC-PRIMITIVE", "SEMGREP-SUBPROCESS-SHELL-TRUE"] }
```

## Key handling

`agentguard sign` and `key show` use (and create on first use) a persistent
ed25519 key at `~/.agentguard/key` — per person, per machine; it never leaves
your home directory. Only **public** keys go in `agentguard.trustedkeys` (one
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
agentguard wrap              # route this project's stdio MCP servers through the shim
agentguard wrap --status     # what's wrapped, and what really runs underneath
agentguard unwrap            # restore the original config
```

`wrap` rewrites `.mcp.json` so each stdio server launches via
`agentguard mcp-shim`, which relays the protocol byte-for-byte (the tool can't
tell the difference) and appends one line per tool call to
`~/.agentguard/audit/<date>.jsonl`:

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

Add an `mcp` section to the same committed `agentguard.policy.json` and the
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

## Exit codes (stable contract)

`0` clean · `1` drift or policy violation · `2` usage error · `3` internal
error. Everything CI needs is in the exit code; `--json` gives machines the
details.
