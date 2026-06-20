# Trust & Verification Features for Eyebrow

**A feature map for solo entrepreneurs and small teams who build with AI agents.**

*Status: research + design proposal, June 2026. Not a commitment — a prioritized menu with
evidence, dashboard mockups, and implementation seams.*

> **Implementation update (June 2026): all 17 features are now built.** The last gaps to close were:
> **B1** — git signed-commit verification (`git verify-commit`) and cosign container verification, each
> setting `Source.Provenance` to satisfy the ladder's top rung, degrading cleanly when the tool or
> object is absent (`internal/adapters/resolve`); **B3** — shadow / unaccounted-extension detection
> (new + locally-defined → `DashArtifact.Shadow`, surfaced as a dashboard banner and drawer badge);
> **C3** — a Policy tab editing `allowPublishers`/`blockPublishers`/`blockArtifacts` via a token-guarded
> `POST /api/policy` that writes the committed `eyebrow.policy.json` (`policystore.Save`); **C4** — per-finding
> "mute with rationale" (`policy.Mute`, `POST /api/mute`); **D2** — one-click per-skill egress allowlist
> editing (`POST /api/egress-allow`, writing the per-server `AllowHosts` the proxy already enforces);
> **E2** — a counts-only posture history (`~/.eyebrow/history.jsonl`), a dashboard "trusted %" trend
> sparkline (`GET /api/history`), and a single-line first-run verdict printed after `eyebrow scan`. All
> shipped with tests and verified end-to-end through the real binary.

> **Implementation update (next frontier — themes F–H, June 2026): all built.** A second wave
> extended the dashboard from "what's installed / is it safe" to "what was used, and who is exposed,"
> each an IO-free domain package the backend joins in:
> **F1** universal usage telemetry (`internal/domain/usage`, joined from the shim's audit log);
> **F2** dormant-then-active "sleeper" detection (old install × drift × first-ever run);
> **F3** capability × usage fusion ranking live findings first (`internal/domain/risk`);
> **F4** the per-artifact event timeline ribbon (`internal/domain/timeline`);
> **G1** team blast-radius from committed content-free snapshots (`internal/domain/fleet`,
> `eyebrow fleet export`/`fleet`, `internal/adapters/fleetstore`);
> **G2** the artifacts × machines inventory/drift heatmap with monoculture & outlier flags;
> **G3** fleet policy conformance (`fleet.CheckConformance`, reusing `policy.ListViolations`);
> **H1** the file-manifest drift diff naming exactly which files moved (`lockfile.DiffFiles`);
> **H2** reachability-aware findings demoting test/example/vendored paths (`internal/domain/reach`);
> **H3** an opt-in, hash-only community reputation signal (`internal/domain/reputation`,
> `internal/adapters/repstore`). All shipped with tests and verified through the real binary.

---

## 0. TL;DR

Eyebrow already does the hard, defensible thing: it inventories every skill, MCP server,
plugin, hook, and rule an AI coding tool installs, hashes them into a committable lockfile,
statically scans them, and detects post-audit mutation ("rug pulls"). Components 1 (`scan`/
`verify`) and 2 (`wrap`/sandbox/egress proxy) are implemented; Component 3 (the dashboard +
team control plane) is in progress, with a local Next.js dashboard already embedded in the
binary.

The market research points to one strategic conclusion: **the wedge is provenance + drift, not
yet-another content scanner.** A dozen well-funded vendors (Snyk/Invariant, Socket, Endor,
Docker's signed MCP catalog, NVIDIA signed skills) are racing to scan *content*. Far fewer
answer the question a small team actually loses sleep over: *"Is what's running today the same
thing I approved last week, and who vouches for it?"* That is exactly what the lockfile already
computes.

For the target buyer — a solo founder or a 2–15 person team — the product **is** the trust. The
research is blunt about what they will and won't adopt:

| They adopt | They ignore / reject |
|---|---|
| Local-first, no account, single binary, <60s to first value | A separate portal they must remember to visit |
| Silent by default; speaks only on real *change* | A score they must interpret with no recommended action |
| One verdict + one action per finding | CVSS-style noise on things they can't fix (the npm-audit death spiral) |
| Git-native approvals reviewable in a PR | Approval workflows needing a server / SSO / RBAC at <15 people |
| Behavioral capability tags ("can now read FS + call network") | Telemetry / "upload your agent config to our cloud to scan" |

The single biggest existential risk for every feature below: **drift-detection false positives.**
If "it changed" fires every time a developer runs `npm update`, Eyebrow becomes `npm audit`
and gets `|| true`'d out of CI. Distinguishing *expected* change (a version bump you initiated)
from *unexpected* drift (post-install mutation) is the hardest and most important UX problem in
this whole document, and several features below exist mainly to defend that signal.

This document maps **17 features across 5 themes**, each with: the problem and the evidence,
how it should display on the dashboard, and how to implement it against the existing seams. They
are tagged **Now / Next / Later** and **Free / Team** so the roadmap doubles as a tiering plan.

---

## 1. Why now — the threat the category is built on

The agent-extension ecosystem is a new package manager with none of the supply-chain controls
the last twenty years taught us to build. The bar to publish a skill is "a `SKILL.md` file and a
one-week-old GitHub account — no code signing, no security review" (Snyk *ToxicSkills*). The data
that justifies the whole category:

- **Snyk ToxicSkills audit (Feb 2026):** 3,984 ClawHub skills analyzed → **36.8% had a flaw,
  13.4% critical, 76 confirmed-malicious with active payloads, 1,467 malicious payloads total.**
  **91% of malicious skills combined prompt injection with traditional malware**, defeating both
  AI safety filters and code scanners. Some persist by rewriting agent memory before removal
  (ClawHavoc).
  <https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/>
- **postmark-mcp (Sept 2025):** the first confirmed malicious MCP server in the wild. Versions
  1.0.0–1.0.15 were clean (building trust); **v1.0.16 added one line that BCC'd every email** to
  an attacker domain. ~1,500 downloads/week. Removal from npm did **not** stop already-installed
  copies. This is the canonical rug pull — and exactly what `verify` catches.
  <https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/>
- **MCPoison (CVE-2025-54136, CVSS 7.2):** Cursor never re-validated an approved MCP config.
  Approve a benign `.cursor/.../mcp.json` once, attacker swaps in a malicious payload later, every
  launch runs attacker commands. Fixed by forcing re-approval on *any* config change.
  <https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/>
- **s1ngularity / Nx (Aug 2025):** first supply-chain attack to **weaponize installed AI CLI
  tools** — its payload invoked the Claude, Gemini, and Amazon Q CLIs on victim machines to hunt
  secrets and crypto-wallet files. ~2,180 accounts, ~7,200 repos, 2,000+ secrets leaked (Wiz).
  <https://www.wiz.io/blog/s1ngularity-supply-chain-attack>
- **Empirical MCP exposure (Astrix, 2025):** of 5,205 OSS MCP servers, **88% require
  credentials, 53% use static long-lived secrets, only 8.5% use OAuth, 79% store keys in env
  vars.** ~1 in 4 MCP servers carries a code-execution risk (Help Net Security, 2026).

**The taxonomy to map findings to** (already partly wired via the `OWASP` field on `finding`):

- **OWASP Agentic Skills Top 10 (2026, `AST01–AST10`)** — maps almost 1:1 to Eyebrow:
  AST01 Malicious Skills, AST02 Supply Chain Compromise, AST03 Over-Privileged, AST04 Insecure
  Metadata, AST05 Unsafe Deserialization, AST06 Weak Isolation, AST07 Update Drift, AST08 Poor
  Scanning, AST09 No Governance, AST10 Cross-Platform Reuse. **AST02/AST07/AST09 are the literal
  inventory + drift + approval model this tool implements.**
  <https://owasp.org/www-project-agentic-skills-top-10/>
- **OWASP MCP Top 10 (2025, `MCP01–MCP10`)** — Token Mismanagement, Privilege Escalation, Tool
  Poisoning, Supply Chain, Command Injection, Intent Flow Subversion, Insufficient AuthN/Z, Lack
  of Audit, Shadow MCP Servers, Context Injection. <https://owasp.org/www-project-mcp-top-10/>

The strategic read: **adopt the mature plumbing, don't rebuild it.** Sigstore/cosign, in-toto,
SLSA, CycloneDX/VEX, npm provenance, and OpenSSF Scorecard are stable and free. The gap none of
them fill is a schema that says *"this MCP server's tool descriptions are signed and haven't
drifted."* That thin, agent-specific layer is the defensible wedge.

---

## 2. The dashboard today, and the proposed information architecture

**Today** (`controlplane/web`, served by `internal/dashboard`): a single page with summary
stat-cards (Critical findings / Total findings / Drifted-unsigned / Verified) and three tabs —
**Inventory & Lockfile**, **Security Findings**, **Rug-pull / Drift** — plus an artifact detail
drawer. Data comes live from `GET /api/scan` (assembled by `dashboard.BuildScan`) with a mock
fallback. There is also an unused `GET /api/audit` endpoint from Component 2.

**The problem with the current IA for this audience:** it leads with *inventory* (a list to
browse) when the research says the killer view is **"what changed since I last looked"** as the
*default landing screen*, with everything else one click behind it. A small team should open the
dashboard, see "nothing changed, you're good" most weeks, and only be pulled in on real change.

**Proposed IA** (the rest of this document fills it in):

```
┌──────────────────────────────────────────────────────────────────────┐
│  Eyebrow · Local           ◐ last scan 2m ago   ⟳   ⌘K  no account  │
├──────────────────────────────────────────────────────────────────────┤
│  TRUST POSTURE                                                         │
│  ●  18 trusted   ▲ 2 changed   ◆ 1 new   ⚑ 1 quarantined              │
│  ╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴   │
│  [ Changes ] [ Inventory ] [ Findings ] [ Drift ] [ Activity ] [ ▸ ]  │
├──────────────────────────────────────────────────────────────────────┤
│  WHAT CHANGED SINCE YOU LAST LOOKED (default)                         │
│                                                                        │
│  ▲ pdf-summarizer  Claude Code · skill        CHANGED — review        │
│    content hash changed after a version bump you didn't run            │
│    + now reads ~/.aws/credentials   + new egress: cdn.pdf-sum.dev      │
│    [ Diff ]  [ Approve ]  [ Quarantine ]  [ Freeze @ v1.4.1 ]          │
│  ─────────────────────────────────────────────────────────────────    │
│  ◆ filesystem-mcp  Codex · mcp                 NEW — never reviewed    │
│    publisher: github.com/modelcontext (unverified) · root: "/"         │
│    [ Diff ]  [ Approve ]  [ Quarantine ]                               │
└──────────────────────────────────────────────────────────────────────┘
```

Two cross-cutting design rules, drawn straight from the research, that every feature obeys:

1. **Verdict, not score.** Numbers build trust *only when they map to an obvious action*. Lead
   with **Trusted / Changed — review / New / Quarantined**; the score and the evidence sit behind
   it. (npm audit's ~80% false-positive rate and CVSS-in-isolation trained a generation of devs
   to ignore "critical." Don't inherit that.)
2. **Remediation lives inside the finding.** Approve / Quarantine / Freeze / Diff are always one
   click from the thing they act on — never a separate "actions" screen.

---

## 3. Theme A — Trust & verdict layer

### A1. Per-artifact Trust Verdict (transparent, additive score → one verdict)

**Status: Next · Free.** **Problem & evidence.** Socket's pattern — a 0–100 score across a few
named dimensions, shown up top for instant context — is the proven model, *but* the research is
emphatic that a tiny team should not have to interpret a number. Translate the score into a
**verdict + recommended action**. A black-box ML score erodes trust; a **hand-recomputable
additive model** builds it.

**The model** (each input already exists in the lockfile / findings):

```
trust = 100
  − Σ finding severity weights        (critical −40, high −20, medium −8, low −2)
  − unverifiable-provenance penalty   (unpinned/remote source, no signature: −15)
  − capability-risk penalty           (exec + network + secret-path read: −10)
  − recent-unexpected-change boost     (drifted since audit: −30)
  + approved-by-trusted-key credit     (signed approval from a trusted key: +20, capped at 100)
→ verdict:  ≥80 Trusted · 50–79 Review · <50 Quarantine-recommended
```

The weights live in one pure, table-driven Go function so they are auditable and unit-testable —
the same discipline the digest/diff core already follows.

**Dashboard.** A single pill on every artifact row and at the top of the detail drawer:
`● Trusted 92` / `▲ Review 64` / `⚑ Quarantine 38`. The drawer expands into the additive
breakdown ("−40 critical RCE finding, −15 unpinned source, +20 signed by alice") so the number
is never mysterious. The four summary stat-cards become **posture buckets** (Trusted / Changed /
New / Quarantined) instead of raw counts.

**Implementation.** New pure package `internal/domain/trust` with `func Score(a artifact.Artifact,
d lockfile.DriftKind, approved bool) Verdict`. Call it inside `dashboard.BuildScan` and add
`Trust int` + `Verdict string` to `DashArtifact`; mirror in `scan-data.ts`. No new IO. Surface
the same verdict in the CLI (`eyebrow list` gets a trust column) so the terminal and dashboard
agree.

### A2. Capability manifest & capability *diff* ("it can now read your filesystem")

**Status: Now (manifest exists) → Next (diff) · Free.** **Problem & evidence.** The single most
trust-building, lowest-noise signal in the research: *"this skill can now read your filesystem and
make outbound network calls — it couldn't last week."* It's a fact, not a CVSS guess. Socket's
whole behavioral-alert model (new network request, new filesystem access, new `child_process`)
maps directly. The lockfile already records `Capabilities{Exec, Network[], Filesystem[]}` per
artifact (`DashCapabilities`), so the manifest is **done** — what's missing is *diffing it across
versions* and surfacing **capability expansion** as its own event class (OWASP AST03
Over-Privileged, MCP02 Scope Creep).

**Dashboard.** In the Changes view and the drawer, render capabilities as tags with a
+added / −removed diff against the locked snapshot:

```
Capabilities          locked            now
exec                  no            →   yes        ⚠ newly added
network               api.openai.com →  api.openai.com, cdn.pdf-sum.dev   ⚠ +1 host
filesystem            ./workspace   →   ./workspace, ~/.aws   ⚠ secret path
```

Capability *expansion* is the headline of the change card; an unchanged capability set on a
content-only change is reassuring context.

**Implementation.** Add `lockfile.CompareCapabilities(locked, current)` to the pure domain
(returns added/removed network hosts, filesystem roots, exec toggle). The egress proxy
(`internal/proxy`) already observes *actual* outbound hosts at runtime — feed those back so the
manifest can show **declared vs observed** network (declared `api.openai.com`, observed also
`cdn.pdf-sum.dev` → flag). Extend `DashCapabilities` with `AddedNetwork`, `RemovedNetwork`,
`AddedFilesystem`, `ExecNewlyAdded`.

### A3. Expected vs unexpected drift (defend the signal)

**Status: Next · Free — and the highest-leverage UX work in this doc.** **Problem & evidence.**
Legitimate skill/MCP updates are frequent. If every `npm update` lights up the dashboard, the
drift signal dies of false positives — the npm-audit failure mode the research warns is *the top
existential risk*. The fix is to distinguish change the developer **initiated** from change that
**appeared on its own**.

**Heuristics** (cheap, local, no ML):

- **Version-bump-correlated:** content hash changed *and* the pinned npm version / git SHA also
  changed *and* the new version resolves cleanly with matching integrity → label **"updated"**
  (expected), not "drifted." A new integrity that matches the registry for the new version is
  evidence of a real release, not tampering.
- **Silent mutation:** content hash changed but **version/SHA did not** → this is the postmark /
  MCPoison shape. Label **"drifted — same version, different bytes"** and rank it loudest. This is
  the rug pull.
- **Provenance-broken:** version changed but integrity/signature no longer verifies → **"drifted —
  unverifiable update."**

**Dashboard.** The Drift tab and Changes view split into **"Updated (expected)"** (quiet, collapsed,
"3 skills updated to new versions you can review") and **"Drifted (unexpected)"** (loud, expanded,
the rug-pull bucket). Same-version-different-bytes gets a distinct red treatment because it has no
benign explanation.

**Implementation.** Extend `lockfile.Compare` / the `DriftKind` enum with `DriftUpdated` (version
*and* content changed together, integrity intact) vs the existing `DriftContentChanged` (now
reserved for content-changed-but-version-stable). `driftStatus` in `dto.go` already collapses the
richer model into the UI's four states — add the `updated` state there. Pure domain change, fully
unit-testable against the existing `Compare` table tests.

---

## 4. Theme B — Provenance & verification

### B1. Publisher identity & provenance binding (the defensible wedge)

**Status: Next · Free core, Team for org policy.** **Problem & evidence.** The official MCP
Registry verifies *who published* (namespace ownership via GitHub/DNS) but **not what the code
does**; registries do no behavioral vetting. Meanwhile the mature plumbing exists and is free:
**Sigstore/cosign** (keyless signing + Rekor transparency log), **npm provenance** (package →
source+build link via OIDC), **in-toto/SLSA** (build provenance attestations), **OpenSSF
Scorecard** (repo hygiene 0–10). Eyebrow already has its own ed25519 signing + trusted-keys
registry for *approvals*; the new work is **verifying upstream provenance** and binding it to the
artifact.

**What to check per source kind:**

| Source | Provenance signal Eyebrow can verify |
|---|---|
| npm | npm provenance attestation (Sigstore) → source repo + build; package integrity already pinned |
| git | commit is signed / tag is signed; repo's OpenSSF Scorecard |
| container MCP | cosign signature + SBOM (Docker MCP Catalog ships these) → `cosign verify` |
| registry entry | official MCP Registry "verified publisher" namespace match |

**Dashboard.** A **provenance ladder** in the drawer, the agent-specific analog of a SLSA level:

```
Provenance     ●●●○  Level 3 / 4
✓ source pinned (npm pdf-summarizer@1.4.2, integrity sha512-…)
✓ npm provenance attestation → github.com/foo/pdf-summarizer @ a1b2c3
✗ publisher not in MCP Registry verified namespace
✗ no Sigstore release signature
```

A broken or absent rung is *information*, not a failure — but "source pinned + provenance
attested + publisher verified" is what a green Trusted verdict should require for a *new* artifact.

**Implementation.** New `ports.ProvenanceVerifier` interface + a `resolve`-adjacent adapter that,
per source kind, shells out to `cosign verify` / `npm view --json` (provenance fields) / reads the
git signature — all behind the existing "degrade, don't crash" contract (no cosign on PATH →
contributes an unverifiable finding, never an error). Results become `finding`s mapped to **AST02
Supply Chain** / **AST04 Insecure Metadata**, plus a `Provenance` struct on `DashArtifact`. This
reuses the *exact* extension seam the architecture already documents for swapping the signature
scheme to cosign/Sigstore.

### B2. Known-malicious & threat-intel feed (offline-first blocklist)

**Status: Next · Free feed, Team for custom feeds.** **Problem & evidence.** postmark-mcp,
ClawHavoc, the ToxicSkills 76 confirmed-malicious skills, the fake-Claude-Code AMOS installers —
these are *known* bad artifacts with known hashes, names, and publisher domains. A small team
can't track them; the tool should. This is the highest-confidence finding class there is: not a
heuristic, a match against ground truth.

**Dashboard.** The loudest possible treatment — a full-width red banner above everything:
`⛔ crypto-price-feed matches a known data-exfiltration campaign (ClawHavoc). Quarantine now.`
with one-click Quarantine. In Inventory, a `known-bad` skull badge overrides the trust pill.

**Dashboard caveat to design for:** this is the one place a stale feed is dangerous (a removed-but-
already-installed package, like postmark, is still live on the machine). Show the feed's
`generatedAt` and let `verify` work fully offline against the last-synced copy.

**Implementation.** Ship a signed, versioned `advisories.json` (hash / name-pattern / publisher
blocklist, OSV-style, mapped to AST01) embedded in the binary and refreshable via a single opt-in
fetch (no telemetry — pull only, like a virus-def update). New pure `internal/domain/advisory`
with `Match(artifact) []Advisory`; wire into `scan` so matches become `critical` findings and into
`policy.Evaluate` so `verify --ci` hard-fails on a known-bad match regardless of threshold.

### B3. Registry & "shadow extension" cross-check

**Status: Later · Free.** **Problem & evidence.** OWASP **MCP09 Shadow MCP Servers** and **AST09
No Governance**: the risk isn't only bad code, it's *unaccounted-for* extensions — an MCP server in
a config nobody remembers adding. Eyebrow's cross-tool discovery already finds everything across
Claude Code, Cursor, Gemini, OpenCode, Codex, Windsurf, Copilot CLI; the new value is reconciling
discovered artifacts against (a) the committed lockfile and (b) optionally the official registry, to
surface "installed but never declared" and "not from any known registry."

**Dashboard.** A small **"Unaccounted"** strip in the Changes view: "2 MCP servers are installed
but not in your lockfile or any known registry," each with Approve/Quarantine. Reuses the existing
`new`/`unsigned` drift states.

**Implementation.** Mostly a presentation join over data `BuildScan` already has (`drift == "new"` +
`Source.Kind == local` + no registry match). Optional registry lookup behind `ports` so it degrades
offline.

---

## 5. Theme C — Workflow & collaboration (the monetization seam)

These are where a solo tool becomes a team tool — and per the research, the natural **free→paid
line**: free protects *one machine*; paid coordinates *policy + approvals + notifications across
people*. Critically, all of it stays **git-native and infra-free** — no server, SSO, or RBAC for a
team this size.

### C1. "What changed since I last looked" + weekly digest

**Status: Now (data) → Next (digest) · Free, digest delivery Team.** **Problem & evidence.** The
research names this the *killer view* and the proven noise-reduction default (Dependabot's weekly
digest). Budget the team **<5 minutes/week**: a near-empty inbox most weeks, attention only on real
change. "X skills unchanged, 1 changed, 0 new permissions."

**Dashboard.** Already mocked as the default landing view in §2. The digest is that view,
serialized: a Markdown/HTML summary the team can also receive in Slack or email.

**Implementation.** A `lockfile.Compare(lastSeen, current)` against a tiny local
`~/.eyebrow/last-seen.json` (the snapshot at last dashboard open / last `digest` run) yields the
delta. `eyebrow digest --since last` renders it for cron/CI. The dashboard "since you last
looked" baseline is just this snapshot, updated on view.

### C2. One-click Approve / Quarantine / Freeze

**Status: Now (approve exists in CLI) → Next (quarantine/freeze + dashboard actions) · Free.**
**Problem & evidence.** Remediation must live inside the finding; quarantine = disable until
reviewed; freeze = pin to an exact version + content hash, the *direct* defense against the
"turns rogue after install via malicious update" attack (postmark, MCPoison). `eyebrow approve`
already exists and writes a (signable) approval into the lockfile.

**Dashboard.** Three buttons on every change/finding card:
- **Approve** → writes a signed approval (existing `approve` + `sign` path), verdict flips to
  Trusted.
- **Quarantine** → marks the artifact disabled; the `wrap` layer refuses to launch it / the
  config rewrite neutralizes it. Loud `⚑ Quarantined` badge.
- **Freeze @ vX** → pins source to the current exact version+hash so any future change is *always*
  drift, never silently accepted.

**Implementation.** The dashboard is read-only today and binds loopback-only with no auth by
design — so *writes* need care. Add `POST /api/approve`, `/api/quarantine`, `/api/freeze`
**behind a one-time CLI-printed local token** (the server prints `dashboard token: …` on launch;
the embedded UI is handed it) so a random browser page still can't drive mutations even on
loopback. Each endpoint calls the existing application use-cases (`approve`, a new `quarantine`
that sets an artifact's lockfile state, `freeze` that rewrites `Source` to the pinned form) and
re-writes the lockfile via `lockstore`. Quarantine enforcement reuses the Component 2 `mcpconfig`
rewrite. Keep every mutation a lockfile diff so it's reviewable in git.

### C3. Allowlist / blocklist (publishers & artifacts)

**Status: Next · Free local, Team for shared.** **Problem & evidence.** A named, top-tier
requested feature: "an approved set that controls acceptable dependencies." Block a publisher
domain, allow a trusted org, never see them again.

**Dashboard.** A **Policy** tab (simple, not an RBAC console): two lists — Allowed publishers /
Blocked publishers & artifacts — each editable inline, each entry showing how many installed
artifacts it matches. Adding "block `*.giftshop.club`" instantly quarantines the postmark-style
match.

**Implementation.** Extend the existing `eyebrow.policy.json` (already has `ignoreRules`,
`requireApproval`, `failOnSeverity`, per-server MCP `denyTools`) with `allowPublishers` /
`blockPublishers` / `blockArtifacts`. `policy.Evaluate` (pure domain) already gates `verify --ci`;
add the list checks there so dashboard, CLI, and CI agree on one committed file. Shared = the file
is committed; that's the whole "team sync," no backend.

### C4. Suppress / ignore with rationale

**Status: Now (exists) → polish · Free.** **Problem & evidence.** Non-negotiable to avoid the
npm-audit "no way to ignore" trap (Snyk-style ignore-with-reason). Already supported:
`policy.ignoreRules` suppresses accepted false positives, and Semgrep rule IDs surface namespaced
(`SEMGREP-…`) precisely so they can be suppressed independently.

**Dashboard.** A "Mute this finding" affordance on each finding that appends to `ignoreRules` with
a required free-text reason and the muter's name, shown as struck-through with a tooltip. Muted ≠
gone — it's auditable in the committed policy.

**Implementation.** `POST /api/mute` (same local-token guard as C2) appends `{rule, reason, by}` to
the policy file via the policy store. Render muted findings collapsed.

### C5. Git-native shared approvals + Slack/CI notifications

**Status: Now (trusted keys + signed approvals exist) → Next (Slack/CI) · Team.** **Problem &
evidence.** Small teams won't stand up approval infrastructure; the winning model is **a committed
lockfile reviewed in a PR diff**, with signed approvals. This already exists: `key show` / `key
trust`, `eyebrow.trustedkeys`, signed approvals, `requireSignedApproval`. The additions are
**notification delivery** (batched, opt-in) so changes reach people where they already are.

**Dashboard.** A small "Notify" config (Slack webhook URL / generic webhook) and a "Send digest
now" button. Notifications are **batched by default** (Slack rejects large payloads and noise
kills adoption) — one digest message, not per-finding spam.

**Implementation.** A `notify` adapter behind a `ports.Notifier` (Slack incoming-webhook + generic
HTTP), driven by `eyebrow digest --notify` in CI/cron. No new persistent service. The PR-review
approval flow is already complete; document it as the team approval story.

---

## 6. Theme D — Runtime & audit (surface what Component 2 already captures)

Component 2 (`wrap`) already audits every MCP `tools/call` and every egress connection to JSONL
under `~/.eyebrow/audit/`, with secret redaction — and the dashboard already has an unused
`GET /api/audit` endpoint and `auditlog.Summarize`. This theme is mostly *surfacing* existing data.

### D1. Activity timeline (tool calls + egress)

**Status: Now (backend done) · Free.** **Problem & evidence.** OWASP **MCP08 Lack of Audit** is a
named risk; "new outbound endpoints" and "credential-access patterns differing from documented
behavior" are exactly what small teams want to be told about. The data exists; only the view is
missing.

**Dashboard.** A new **Activity** tab: a reverse-chronological timeline of tool calls (server ·
tool · outcome, arguments shown only as a content digest — never raw, by design) and egress events
(host · bytes in/out · redactions applied). Filters mirror the `auditlog.Filter` the API already
takes (server / tool / status / kind). A summary strip ("142 tool calls, 3 denied, 11 egress hosts,
2 redactions today").

**Implementation.** Wire the existing `/api/audit` into a React `<ActivityPanel>` using the same
fetch/fallback pattern as `useScan`. Essentially zero backend work — the endpoint, filter, and
summary types already ship.

### D2. Egress map & per-skill egress allowlist

**Status: Next · Free view, Team for shared allowlists.** **Problem & evidence.** The egress proxy
already enforces host policy and counts bytes per connection; an unexpected new host is a primary
"tell me about this" signal (the postmark BCC, the wallet-exfil POST). Pair the observed egress
with the *declared* network capability (A2) to flag "talked to a host it never declared."

**Dashboard.** A compact per-artifact egress list in the drawer (hosts contacted, allowed vs
blocked, bytes), and a global "Egress" view: which artifact talked to which host. New/undeclared
hosts highlighted. One-click "allow this host for this skill" → writes a policy host rule.

**Implementation.** Join `audit` egress events (already have host + bytes + `kind:"egress"`) by
server to the artifact inventory; the allowlist write reuses the per-server policy host rules the
proxy (`policy.DecideHost`) already enforces. The enforcement is real because the sandbox confines
the server's network to the proxy port.

---

## 7. Theme E — Reporting & posture

### E1. SBOM / VEX export

**Status: Later · Team.** **Problem & evidence.** Even tiny teams increasingly get asked "what's
your supply chain" by their first enterprise customer. **CycloneDX** (OWASP, security-focused,
embeds VEX) is the right format; **VEX** lets Eyebrow say "this skill bundles a vulnerable lib
but the vulnerable path isn't reachable from agent context" — a strong, noise-cutting
differentiator. Eyebrow already *has* the component inventory and per-file hashes the SBOM needs.

**Dashboard.** An "Export" button → `eyebrow.cdx.json` (CycloneDX) and a human PDF/HTML posture
report. Nothing to interpret live; it's an artifact to hand off.

**Implementation.** A `report` adapter variant emitting CycloneDX from the existing lockfile model
(components = artifacts, hashes = `Files`, plus a VEX section from findings). Pure mapping over data
already in hand.

### E2. Posture trend & onboarding "first verdict"

**Status: Later · Free.** **Problem & evidence.** Time-to-first-value must be one command, <60s,
zero account. A solo founder's very first `scan` should end on a **single verdict**: "Scanned 21
artifacts across 3 tools. 18 trusted, 2 need review, 1 quarantine-recommended. Nothing has drifted."
Over time, a sparkline of "trusted %" gives a sense of direction without a portal to visit.

**Dashboard.** A one-line posture headline at the top (already partly there) plus a small trend
sparkline fed by the periodic `digest` snapshots. The first-run experience surfaces the same verdict
in the terminal so the dashboard is optional, not required.

**Implementation.** Append each `digest`/scan summary to a local `~/.eyebrow/history.jsonl`
(counts only, no content); the trend reads it. The first-run verdict is a CLI reporter variant over
the trust scores from A1.

---

## 8. Prioritized roadmap & tiering

Ordered by *adoption leverage per unit of build effort*, given how much already exists.

| # | Feature | Theme | Effort | When | Tier | Leans on (existing) |
|---|---|---|---|---|---|---|
| D1 | Activity timeline | Runtime | XS | **Now** | Free | `/api/audit`, `Summarize` already ship |
| C1 | "What changed" view + baseline | Workflow | S | **Now** | Free | `lockfile.Compare`, drift states |
| A2 | Capability diff & expansion | Trust | S | **Now→Next** | Free | `Capabilities` recorded; proxy observes egress |
| C2 | Approve / Quarantine / Freeze | Workflow | M | **Next** | Free | `approve`+`sign`; needs write API + local token |
| A3 | Expected vs unexpected drift | Trust | M | **Next** | Free | `Compare`/`DriftKind` (pure domain) |
| A1 | Trust verdict (additive) | Trust | M | **Next** | Free | findings + drift + approvals all in `BuildScan` |
| B2 | Known-malicious feed | Provenance | M | **Next** | Free | `scan` + `policy.Evaluate` gates |
| B1 | Provenance binding (cosign/npm) | Provenance | M–L | **Next** | Free | documented signer/resolver seams |
| C3 | Allow/block lists | Workflow | S | **Next** | Free/Team | `policy.json` + `Evaluate` |
| C4 | Suppress with rationale | Workflow | XS | **Now** | Free | `ignoreRules` already exists |
| C5 | Slack/CI digest delivery | Workflow | S | **Next** | Team | trusted-keys/approvals done; add `Notifier` |
| D2 | Egress map + allowlist | Runtime | S | **Next** | Free/Team | proxy host policy + audit egress events |
| B3 | Shadow/registry cross-check | Provenance | S | **Later** | Free | discovery + drift `new` state |
| E1 | SBOM / VEX export | Reporting | M | **Later** | Team | lockfile components + file hashes |
| E2 | Posture trend + first verdict | Reporting | S | **Later** | Free | digest snapshots + trust scores |

**The "Now" set is mostly surfacing data the binary already computes** — the fastest path to a
dashboard a small team will actually open. Everything write-related (C2/C3/C4) shares one piece of
new infrastructure: a **local mutation token** so the no-auth, loopback-only dashboard can safely
gain write endpoints without becoming an unauthenticated control plane (the package doc explicitly
warns against that).

---

## 9. Cross-cutting implementation notes

- **Keep the core pure.** Trust scoring (A1), drift classification (A3), capability diff (A2),
  advisory matching (B2) all belong in `internal/domain` as IO-free, table-driven functions — same
  discipline as `digest`/`Compare`. The dashboard and CLI become thin renderers of one truth.
- **One data shape, two front-ends.** Every verdict/badge added to `DashArtifact` should also
  appear in `eyebrow list` so the terminal-first solo user never *needs* the dashboard. Mirror
  each Go DTO field in `controlplane/web/lib/scan-data.ts`.
- **Writes need a guard.** The dashboard is deliberately auth-free because it has no remotely
  reachable surface; the moment it can mutate the lockfile, add a launch-printed local token bound
  into the embedded UI. Loopback-only + DNS-rebind guard stay; the token defeats a malicious local
  page driving mutations.
- **Degrade, don't crash.** Provenance verification (B1), the advisory fetch (B2), and notifications
  (C5) must all no-op cleanly when cosign/npm/network is absent — contributing a finding, never an
  error, exactly as resolution failures already do.
- **Offline-first stays sacred.** The only network the product *initiates* is opt-in pull (advisory
  feed, provenance lookups). No telemetry, no config upload — that is both the security posture and
  the marketing pitch for this audience.
- **Git is the backend.** Approvals, policy, allowlists, trusted keys are all committed files
  reviewable in a PR. That is the entire "team" story for ≤15 people; defer RBAC/SSO/audit-portal to
  a real enterprise tier.

---

## 10. Open questions to validate before building

1. **Drift false-positive rate is the whole bet** (A3). Validate the version-bump-correlation
   heuristic against real update streams before shipping; if "updated" misclassifies tampering even
   occasionally, the feature is net-negative.
2. **Where does Eyebrow run** — per-developer machine, CI, or both? It changes the
   seat-vs-repo pricing axis and whether the digest is a cron job or a CI step.
3. **Willingness to pay for this exact category is unproven** — the agent-skills/MCP security market
   is <1 year old. The pricing in §8 (free = one machine's protection; Team = shared
   policy/approvals/notifications) is inferred from npm/dependency-tool analogs; validate with
   10–15 customer-discovery calls before committing tiers.
4. **Semantic danger on first install** (B1/B2 partially cover it): hash-based drift catches *edits*
   but not a skill that's malicious on day one via prompt-injection in its text. Pair lock/drift
   with the first-install static + provenance scan, and be honest in the UI about what locking does
   and doesn't prove.

---

## Appendix — sources

Threat landscape & incidents:
Snyk ToxicSkills <https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/> ·
Snyk postmark-mcp <https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/> ·
Check Point MCPoison <https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/> ·
Wiz s1ngularity <https://www.wiz.io/blog/s1ngularity-supply-chain-attack> ·
Invariant Labs tool poisoning <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks> ·
Trail of Bits line-jumping <https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/> ·
Astrix State of MCP Security 2025 <https://astrix.security/learn/blog/state-of-mcp-server-security-2025/> ·
Help Net Security — AI agent skills blind spots <https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/> ·
obot.ai MCP/skills supply chain <https://obot.ai/blog/mcp-security-agent-skills-supply-chain/>

Taxonomies:
OWASP Agentic Skills Top 10 <https://owasp.org/www-project-agentic-skills-top-10/> ·
OWASP MCP Top 10 <https://owasp.org/www-project-mcp-top-10/> ·
OWASP GenAI Top 10 for Agentic Apps <https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/>

Standards & tooling:
Sigstore/cosign <https://blog.sigstore.dev/cosign-verify-bundles/> ·
SLSA <https://slsa.dev> · in-toto <https://in-toto.io> ·
CycloneDX VEX <https://cyclonedx.org/capabilities/vex/> ·
OpenSSF build provenance <https://repos.openssf.org/build-provenance-for-all-package-registries.html> ·
OpenSSF Scorecard <https://github.com/ossf/scorecard> ·
Snyk + Invariant mcp-scan <https://invariantlabs-ai.github.io/docs/mcp-scan/scanning/> ·
Socket behavioral analysis <https://docs.socket.dev/docs/socket-package> ·
Endor Labs AURI <https://www.endorlabs.com/learn/introducing-security-for-ai-coding-agents-and-workstations> ·
Docker MCP Catalog signing <https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/> ·
MCP Registry preview <https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/>

Adoption, UX & GTM:
Why developers ignore security tools <https://www.appknox.com/blog/why-developers-ignore-security-tools> ·
Why npm audit is broken <https://www.pkgpulse.com/guides/why-npm-audit-is-broken> ·
Alert fatigue & dashboard UX <https://medium.com/design-bootcamp/alert-fatigue-and-dashboard-overload-why-cybersecurity-needs-better-ux-1f3bd32ad81c> ·
Socket trust score review <https://appsecsanta.com/socket> ·
Dependabot FP auto-dismiss & digest <https://github.blog/changelog/2023-05-02-dependabot-alerts-now-automatically-dismiss-false-positives-for-npm-public-beta/> ·
Dependency pinning / lockfile approvals <https://devsecopsschool.com/blog/dependency-pinning/> ·
Semgrep — security as path of least resistance <https://semgrep.dev/blog/2026/security-should-be-the-path-of-least-resistance/> ·
Local-first tooling <https://www.inkandswitch.com/essay/local-first/> ·
Dev-tool pricing/tiering <https://www.getmonetizely.com/articles/how-to-price-developer-tools-feature-gating-and-tier-strategies-for-code-quality-platforms-74f84>
