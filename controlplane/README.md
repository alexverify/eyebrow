# controlplane/ — team tier (seam, Component 3)

The self-hosted control plane: policy, signature/trust registry, approved
lockfile snapshots, audit-log ingest, and a dashboard. Empty today; opt-in and
not required for the CLI to work.

## Planned layout

```
controlplane/
├── api/          # Go (toolchain consistency) or Node/Fastify API
├── migrations/   # Postgres schema
└── web/          # Next.js + Tailwind dashboard
```

## Responsibilities

- **Policy store** — org-wide allowlists, required-signature rules, blocklists,
  severity thresholds.
- **Signature/trust registry** — trusted keys/authors; approved-artifact hashes
  shared across the team.
- **Approved-lockfile snapshots** — the source of truth `verify --ci` checks.
- **Audit-log ingest** — runtime egress + tool-call events (opt-in), queryable.
- **Dashboard** — team inventory, drift/rug-pull alerts, findings triage, audit
  timeline, policy editor.

## Data model (Postgres, core tables)

`orgs`, `users`, `machines`, `policies`, `trusted_keys`,
`artifacts` (org-shared, content-hash keyed), `approvals`, `lockfile_snapshots`,
`audit_events`. Index `audit_events (org_id, ts)` and `artifacts (content_hash)`.

The CLI talks to this through `internal/client`.
