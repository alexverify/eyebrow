# assay privacy contract

assay is **offline-first**. Every core command — `scan`, `verify`, `wrap`,
`audit`, `dashboard`, `fleet` — works with no network and sends nothing off your
machine. This document states exactly what leaves a machine, and only ever does
so when **you opt in** by pointing the CLI at a control plane (`--server` /
`ASSAY_SERVER`). With no server configured, none of the following applies.

## What never leaves your machine

- **File contents and source code.** assay hashes files locally; only hashes are
  ever recorded. The line-level drift diff (H1b) is computed from a **local**,
  gitignored cache (`.assay/snapshots`) and is never uploaded.
- **Secrets and raw tool arguments.** The MCP shim records tool-call arguments
  only as a SHA-256 **digest**, and redacts secrets from egress bodies before
  they are sent. Raw values are never stored, so they can never be uploaded.
- **Environment variable values.** Only env *keys* (names) are ever surfaced,
  never values.
- **Your signing private key.** Only the public key is shared, and only when you
  choose to (`key show`, or an admin adding it to the registry).
- **The reputation corpus lookup.** The community trust signal is a local,
  hash-keyed map lookup — it sends nothing, even when configured.

## What leaves only when you opt in to a control plane

| You run | What is sent | Shape |
|---|---|---|
| `assay fleet push` | a **content-free snapshot**: per-artifact id, name, kind, content hash, source ref, and your local drift/verdict | no code, no secrets, no file bytes — exactly what `fleet export` writes to a committed file |
| `assay audit push` | your **audit events**: tool and server names, egress **hostnames**, HTTP methods, byte counts, redaction counts, statuses, timestamps, and argument **digests** | no raw arguments, no secrets, no response bodies |
| `assay verify --server`, `assay fleet verify --server` | nothing is uploaded — these **pull** org policy and trusted keys (reads) | — |

Two honesty notes about `audit push`:

- It **does** reveal which tools/servers ran and **which hostnames** wrapped
  servers connected to (or were blocked from). That is the point of team
  egress/usage observability — but it is information about your activity, so it
  is strictly opt-in and never sent without `--server`.
- It carries argument **digests**, not arguments. A digest lets an investigator
  *confirm* a known value was passed; it does not disclose an unknown one.

## Scoping and isolation

A control-plane request is authenticated by a per-machine **bearer token** that
scopes it to exactly one org. The server stores each org's data in isolation; a
token for one org can never read or write another's.

## Self-hosting

The control plane is a **self-hostable** single binary (`assay serve`) with a
zero-dependency file store by default. A team that runs it themselves keeps all
of the above on their own infrastructure — assay operates no hosted service.

## Degrade, never surprise

If a server is unreachable or has no policy for your org, the CLI **falls back to
local** (the committed `assay.policy.json`, the local trusted-keys registry).
Adopting a server never silently changes a gate you did not configure, and an
unreachable server never blocks CI.
