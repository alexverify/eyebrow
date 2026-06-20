# Phase 4 — hosted team control plane (Component 3b): scope

Status: **scoping only, not started.** This is the one remaining large item from
the next-steps plan. Unlike Phases 1–3 (self-contained vertical slices), it
needs product/infra decisions before code. This doc scopes the work, grounds it
in what already exists, names the genuine decisions, and breaks it into
shippable slices.

## Decisions locked (confirmed)

- **Deployment:** self-hostable single Go binary (`assay serve`); multi-tenant
  SaaS deferred (same binary with tenancy on by default later).
- **API language:** Go — reuse the pure domain packages verbatim, one toolchain.
- **Auth:** per-machine bearer tokens (admin-issued, scoped) for the CLI;
  OIDC/SSO for humans in the web dashboard; org-scoped roles, row-level `org_id`
  isolation.

These set the directory layout (`controlplane/api` in Go), the dependency set
(domain core + Postgres driver, isolated to the API binary), and the schema
(org-scoped, token + OIDC identity).

---

## 1. The invariant this must not break

Offline-first stays the **default**, forever. Today "git is the backend":
lockfiles, approvals, trusted keys, and fleet snapshots are committed files; the
dashboard and `fleet verify` aggregate whatever they find, no server required.
That model is correct and caps cleanly around ~15 people (a shared repo, manual
snapshot commits). The control plane is the **opt-in** answer beyond that — and
it must:

- be **additive**: every CLI command keeps working with no server configured;
- **degrade to local** when the server is unreachable (advisory-feed contract,
  same as the offline advisory/reputation today);
- send nothing the offline model wouldn't already commit — the snapshot stays
  **content-free** (ids, hashes, drift/verdict; no code, no secrets).

If a slice can't hold these three, it's mis-scoped.

---

## 2. What already exists to build on

- **`internal/client/doc.go`** — a stub naming the planned endpoints
  (`POST /v1/lockfiles`, `GET /v1/policy`, `POST /v1/audit`,
  `GET /v1/registry/keys`, `POST /v1/artifacts/:id/approve`, `GET /v1/alerts`).
- **`controlplane/README.md`** — a planned layout (`api/`, `migrations/`,
  `web/`) and a Postgres data model (`orgs`, `users`, `machines`, `policies`,
  `trusted_keys`, `artifacts`, `approvals`, `lockfile_snapshots`,
  `audit_events`).
- **`controlplane/web`** — the **existing** Next.js dashboard. It already renders
  `BuildScan` / `fleet.Report` / `fleet.Conformance` shapes. The hosted UI is
  the *same app with a different data source* — not a rewrite.
- **Pure, server-reusable domain functions** (no IO, already tested):
  `lockfile.Build/Compare/Classify`, `fleet.Aggregate`, `fleet.CheckConformance`,
  `fleet.Gate`, `policy.Evaluate/ListViolations`, `dashboard.BuildScan`,
  `usage.Summarize`, `reputation.Source.Lookup`, `posture.Summarize`.
  **These move server-side unchanged** — the control plane is mostly transport,
  auth, and storage around logic that already exists and is tested.

The shape of Phase 4 is therefore: a thin client, a thin API, Postgres, and a
data-source swap in the web app — wrapped around the existing pure core.

---

## 3. Reconcile with everything F–H added

The control-plane README predates Phases F–H. The scope must now also cover:

| Capability (local today) | Hosted equivalent |
|---|---|
| Fleet snapshots in `.assay/fleet` (G1–G3) | `POST /v1/snapshots`; server runs `fleet.Aggregate`/`CheckConformance`/`Gate` |
| `assay fleet verify` CI gate (Phase 3) | same gate, server-side, over submitted snapshots; CI calls the API instead of reading a dir |
| Usage activations + MCP audit (F1b) | `POST /v1/audit` batched ingest; server runs `usage.Summarize` for fleet-wide usage |
| Reputation corpus (H3, local hash-only) | `GET /v1/reputation/:hash` — **unlocks H3b**, the live hash-only lookup behind the existing `reputation.Source` seam |
| Snapshot blobs for line diffs (H1b) | **out of scope / opt-in only** — bytes are local cache by design; hosting them re-opens the secret/bloat question. Keep line diffs local. |
| Trusted keys registry (committed) | `GET /v1/registry/keys` |
| Approvals (signed, in lockfile) | `POST /v1/artifacts/:id/approve` workflow + server-verified signatures |

---

## 4. Target architecture

```
 assay CLI                          control plane                      Postgres
 ─────────                          ─────────────                      ────────
 internal/client  ──HTTP(S)──▶  controlplane/api (Go)  ──▶  orgs/policies/snapshots/
   (opt-in port impls)            • authn/z (org, machine)       audit/approvals/keys
   • submit snapshot              • reuse pure domain fns
   • pull policy/keys             • multi-tenant (org_id)
   • ingest audit (batched)       • serve BuildScan/fleet shapes
   • lookup reputation
        │                                  │
        │                                  ▼
        │                          controlplane/web  (existing Next.js,
        ▼                            data source swapped local→/v1)
 falls back to local on any error
```

Key property: the API **serves the same JSON shapes** the local dashboard
already produces, so `controlplane/web` changes only its fetch layer.

---

## 5. The genuine decisions (need product/infra input)

Each materially changes the build. Recommendation given; all are the user's call.

1. **Deployment model.** Self-hosted single binary (`assay serve`, the team runs
   it) **vs** managed multi-tenant SaaS (we host).
   *Recommendation: self-hostable single Go binary first* — matches the
   zero-dependency, auditable-supply-chain ethos ("a security tool you can run
   yourself"), defers the hardest SaaS concerns (billing, data residency, our
   own breach surface), and a multi-tenant SaaS is the *same binary* with
   tenancy on by default later.

2. **API language.** Go **vs** Node/Fastify (the README floated both).
   *Recommendation: Go* — reuse the pure domain packages verbatim (the whole
   value prop of "same shapes"), one toolchain, one `make check`, no second
   dependency tree to audit.

3. **AuthN/Z.** *Recommendation:* per-machine **bearer tokens** (issued by an
   org admin, scoped to submit/pull) for the CLI; **OIDC/SSO** for humans in the
   web dashboard; org-scoped roles (admin/member/CI). Row-level `org_id`
   isolation, no cross-tenant queries.

4. **Storage.** Postgres (per the README). *Recommendation: confirm* — it fits
   the relational model and `audit_events (org_id, ts)` indexing. One dependency,
   isolated to the API binary, never the CLI.

5. **Privacy contract (must be written before any ingest ships).** Exactly what
   leaves a machine, that it's content-free, that audit args stay digested, that
   reputation lookups send only a hash. This is a *published document*, not a
   code detail — it's also what makes H3b acceptable.

6. **Sync direction & cadence.** Push snapshots on `scan`/explicit `assay push`
   vs a daemon. *Recommendation:* explicit/opt-in push + pull on `verify --ci`;
   no background daemon in v1.

---

## 6. Shippable slices (each independently valuable, offline-safe)

- **4a — Ingest + aggregate (the spine). ✅ SHIPPED.** `internal/controlplane`
  (Service + Store port + HTTP server + machine-token auth), `internal/adapters/
  cpstore` (zero-dep file store; Postgres deferred to a later scale adapter),
  `internal/client` (Submit/Fleet/Health), CLI `assay serve` / `fleet push` /
  `fleet --server`. `GET /v1/fleet` is `fleet.Aggregate` verbatim — the hosted
  report equals the local one. Proven end-to-end (two machines → 2/2). ~L.
- **4b — Policy & trusted-keys pull. ✅ SHIPPED.** A read-mostly `Config` port
  (policy + trusted keys) distinct from the snapshot `Store`; `GET /v1/policy`
  (404 → keep local) and `GET /v1/registry/keys`; cpstore file backend
  (`<org>/policy.json`, `trustedkeys.json`); client `Policy`/`TrustedKeys`;
  `verify` and `fleet verify` prefer the server, fall back to local. Proven
  end-to-end (server policy fails the fleet gate with no local policy file). ~M.
- **4c — Hosted CI gate. ✅ SHIPPED.** `GET /v1/gate` runs `fleet.Gate`
  server-side over the org's submitted snapshots + configured policy;
  `assay fleet verify --server` gates the pushed fleet (no local dir), exit codes
  unchanged. Proven end-to-end. ~S (pure fn reuse).
- **4d — Audit/usage ingest + alerts. ✅ SHIPPED.** `POST /v1/audit` (batched,
  content-free), `GET /v1/alerts`; per-org audit storage (MemStore + cpstore
  JSONL); pure `internal/domain/alert` (drift/quarantine from the fleet,
  blocked-egress/denied-tool from audit — honest about no finding-level alerts
  since snapshots are content-free); CLI `audit push` + `alerts`. Published the
  privacy contract (`docs/privacy.md`) as the scope required. Proven end-to-end.
  Note: sleeper/new-critical alerts deferred — they need richer (non-content-free)
  snapshots, named rather than faked. ~L.
- **4e — Web dashboard on hosted data. ✅ SHIPPED (loopback variant).** Chose the
  loopback-dashboard-on-hosted-data approach (user decision): `assay dashboard
  --server` keeps the loopback-only UI and points its Fleet/Conformance/Alerts/
  Reputation deps at the control plane (`GET /v1/conformance` added; new
  `/api/alerts` + a Team Alerts tab). No OIDC/network UI — machine token only,
  per-artifact view stays local (content-free hosted data). A centrally-hosted
  multi-user UI with SSO is left as a future extension. ~M.
- **4f — H3b live reputation. ✅ SHIPPED.** Org reputation corpus in `Config`
  (cpstore `reputation.json`); `POST /v1/reputation` (batch, returns matches
  only); client `Reputation`; dashboard `Reputation` dep now resolves the
  inventory hashes from a local file or the server; `assay reputation` command.
  Privacy: sends only hashes held, server returns matches only. ~S–M.

Recommended order: 4a → 4b → 4c → (4d ∥ 4e) → 4f. Each ships behind an opt-in
`--server`/config and degrades to local.

---

## 7. Out of scope (v1)

- Hosting line-diff blobs (H1b) — bytes stay a local cache by design.
- Billing/metering, data residency regions, SCIM.
- A background sync daemon.
- Replacing any offline path — all of them remain the default.

---

## 8. Risks

- **Scope creep into SaaS.** Mitigate: ship the self-hosted binary first; tenancy
  is a column, not a rewrite.
- **Privacy regression.** Mitigate: the content-free guarantee is enforced at the
  client serialization boundary and covered by a test that the submitted payload
  contains no file bytes/secrets; publish the contract before 4d.
- **Two dependency trees.** Mitigate: Go API reusing the domain core keeps it to
  one (plus Postgres driver, isolated to the API binary).
- **Auth surface** is genuinely new attack surface for a security tool — needs a
  real threat model before 4d/4e.

---

## 9. To confirm before writing 4a

Deployment model (self-hosted vs SaaS), API language (Go vs Node), and the auth
model. These three gate the directory layout, the dependency set, and the schema.
Everything else can follow defaults above.
