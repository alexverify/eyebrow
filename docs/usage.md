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

## Exit codes (stable contract)

`0` clean · `1` drift or policy violation · `2` usage error · `3` internal
error. Everything CI needs is in the exit code; `--json` gives machines the
details.
