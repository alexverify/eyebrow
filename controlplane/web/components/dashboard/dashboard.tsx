"use client"

import { useMemo, useState } from "react"
import {
  Search,
  Boxes,
  ShieldAlert,
  GitCompareArrows,
  FileCode2,
  ChevronRight,
  Terminal,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import {
  KIND_LABELS,
  PATTERN_LABELS,
  type Agent,
  type Artifact,
  type ArtifactKind,
} from "@/lib/scan-data"
import {
  getAllFindings,
  severityCounts,
  driftCounts,
  topSeverity,
  SEVERITY_STYLES,
} from "@/lib/scan-utils"
import { useScan } from "@/lib/use-scan"
import { StatCard } from "@/components/dashboard/stat-card"
import { SeverityBadge, DriftBadge } from "@/components/dashboard/badges"

type TabId = "inventory" | "findings" | "drift"

const TABS: { id: TabId; label: string; icon: typeof Boxes }[] = [
  { id: "inventory", label: "Inventory & Lockfile", icon: Boxes },
  { id: "findings", label: "Security Findings", icon: ShieldAlert },
  { id: "drift", label: "Rug-pull / Drift", icon: GitCompareArrows },
]

export function Dashboard() {
  const { artifacts, loading, live } = useScan()
  const [tab, setTab] = useState<TabId>("inventory")
  const [query, setQuery] = useState("")
  const [agentFilter, setAgentFilter] = useState<Agent | "all">("all")
  const [kindFilter, setKindFilter] = useState<ArtifactKind | "all">("all")

  const sev = useMemo(() => severityCounts(artifacts), [artifacts])
  const drift = useMemo(() => driftCounts(artifacts), [artifacts])
  const findings = useMemo(() => getAllFindings(artifacts), [artifacts])

  // Agents present in the data drive the filter, so it tracks whatever tools
  // were actually discovered rather than a fixed list.
  const agents = useMemo(
    () => Array.from(new Set(artifacts.map((a) => a.agent))).sort() as Agent[],
    [artifacts],
  )

  const filteredArtifacts = useMemo(() => {
    return artifacts.filter((a) => {
      const matchesQuery =
        query.trim() === "" ||
        a.name.toLowerCase().includes(query.toLowerCase()) ||
        a.source.toLowerCase().includes(query.toLowerCase())
      const matchesAgent = agentFilter === "all" || a.agent === agentFilter
      const matchesKind = kindFilter === "all" || a.kind === kindFilter
      return matchesQuery && matchesAgent && matchesKind
    })
  }, [artifacts, query, agentFilter, kindFilter])

  const driftedArtifacts = useMemo(
    () => artifacts.filter((a) => a.drift === "drifted" || a.drift === "unsigned"),
    [artifacts],
  )

  const totalFindings = findings.length
  const criticalCount = sev.critical
  const driftedCount = drift.drifted + drift.unsigned

  return (
    <div className="mx-auto max-w-[1200px] px-6 py-8">
      {/* Page header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-mono text-2xl font-semibold tracking-tight text-foreground">
            Local Scan
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {loading
              ? "scanning…"
              : `${artifacts.length} artifacts inventoried across ${agents.length} agents`}{" "}
            ·{" "}
            <span className="font-mono text-foreground">{live ? "live scan" : "demo data"}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 font-mono text-xs text-muted-foreground">
          <Terminal className="h-3.5 w-3.5 text-primary" />
          <span className="text-foreground">npx agentguard scan</span>
        </div>
      </div>

      {/* Summary stats */}
      <div className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Critical findings"
          value={criticalCount}
          hint="require immediate review"
          accent={criticalCount > 0 ? "critical" : "ok"}
        />
        <StatCard label="Total findings" value={totalFindings} hint="across all artifacts" accent="high" />
        <StatCard
          label="Drifted / unsigned"
          value={driftedCount}
          hint="changed since audit"
          accent={driftedCount > 0 ? "critical" : "ok"}
        />
        <StatCard
          label="Verified"
          value={drift.verified}
          hint="match locked hash"
          accent="ok"
        />
      </div>

      {/* Tabs */}
      <div className="mt-8 flex flex-wrap gap-1 border-b border-border">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "inline-flex items-center gap-2 border-b-2 px-3 py-2.5 font-mono text-sm transition-colors",
              tab === id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="mt-6">
        {tab === "inventory" && (
          <InventoryPanel
            artifacts={filteredArtifacts}
            agents={agents}
            query={query}
            setQuery={setQuery}
            agentFilter={agentFilter}
            setAgentFilter={setAgentFilter}
            kindFilter={kindFilter}
            setKindFilter={setKindFilter}
          />
        )}
        {tab === "findings" && <FindingsPanel findings={findings} />}
        {tab === "drift" && <DriftPanel artifacts={driftedArtifacts} />}
      </div>
    </div>
  )
}

/* ----------------------------- Inventory ----------------------------- */

function InventoryPanel({
  artifacts: rows,
  agents,
  query,
  setQuery,
  agentFilter,
  setAgentFilter,
  kindFilter,
  setKindFilter,
}: {
  artifacts: Artifact[]
  agents: Agent[]
  query: string
  setQuery: (v: string) => void
  agentFilter: Agent | "all"
  setAgentFilter: (v: Agent | "all") => void
  kindFilter: ArtifactKind | "all"
  setKindFilter: (v: ArtifactKind | "all") => void
}) {
  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by name or source…"
            className="pl-9 font-mono text-sm"
          />
        </div>
        <FilterSelect
          value={agentFilter}
          onChange={(v) => setAgentFilter(v as Agent | "all")}
          options={[{ value: "all", label: "All agents" }, ...agents.map((a) => ({ value: a, label: a }))]}
        />
        <FilterSelect
          value={kindFilter}
          onChange={(v) => setKindFilter(v as ArtifactKind | "all")}
          options={[
            { value: "all", label: "All types" },
            { value: "skill", label: "Skills" },
            { value: "mcp", label: "MCP Servers" },
            { value: "plugin", label: "Plugins" },
          ]}
        />
      </div>

      <div className="mt-4 overflow-hidden rounded-lg border border-border">
        <div className="hidden grid-cols-[1.6fr_0.7fr_0.8fr_1.4fr_0.9fr_0.7fr] gap-4 border-b border-border bg-muted/40 px-4 py-2.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground md:grid">
          <span>Artifact</span>
          <span>Type</span>
          <span>Agent</span>
          <span>Content hash</span>
          <span>Status</span>
          <span className="text-right">Findings</span>
        </div>
        {rows.length === 0 ? (
          <p className="px-4 py-10 text-center text-sm text-muted-foreground">
            No artifacts match your filters.
          </p>
        ) : (
          rows.map((a) => {
            const sev = topSeverity(a)
            return (
              <div
                key={a.id}
                className="grid grid-cols-1 gap-2 border-b border-border px-4 py-3 last:border-0 transition-colors hover:bg-muted/30 md:grid-cols-[1.6fr_0.7fr_0.8fr_1.4fr_0.9fr_0.7fr] md:items-center md:gap-4"
              >
                <div className="flex items-center gap-2.5">
                  <FileCode2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm font-medium text-foreground">{a.name}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {a.source} · v{a.version}
                    </p>
                  </div>
                </div>
                <span className="font-mono text-xs text-muted-foreground">{KIND_LABELS[a.kind]}</span>
                <span className="text-xs text-foreground">{a.agent}</span>
                <span className="truncate font-mono text-xs text-muted-foreground">{a.hash}</span>
                <span>
                  <DriftBadge status={a.drift} />
                </span>
                <span className="md:text-right">
                  {sev ? (
                    <span className={cn("font-mono text-sm font-semibold", SEVERITY_STYLES[sev].text)}>
                      {a.findings.length}
                    </span>
                  ) : (
                    <span className="font-mono text-sm text-ok">0</span>
                  )}
                </span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 rounded-md border border-border bg-card px-3 font-mono text-xs text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

/* ----------------------------- Findings ----------------------------- */

function FindingsPanel({ findings }: { findings: ReturnType<typeof getAllFindings> }) {
  const [open, setOpen] = useState<string | null>(findings[0]?.id ?? null)

  return (
    <div className="flex flex-col gap-2">
      {findings.map((f) => {
        const isOpen = open === f.id
        return (
          <div key={f.id} className="overflow-hidden rounded-lg border border-border bg-card">
            <button
              onClick={() => setOpen(isOpen ? null : f.id)}
              className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/30"
            >
              <ChevronRight
                className={cn(
                  "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
                  isOpen && "rotate-90",
                )}
              />
              <SeverityBadge severity={f.severity} />
              <span className="min-w-0 flex-1 truncate text-sm text-foreground">{f.title}</span>
              <span className="hidden font-mono text-xs text-muted-foreground sm:inline">
                {f.artifactName}
              </span>
            </button>
            {isOpen && (
              <div className="border-t border-border px-4 py-4">
                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-muted-foreground">
                  <span className="rounded border border-border bg-muted/40 px-2 py-0.5">
                    {PATTERN_LABELS[f.pattern]}
                  </span>
                  <span>·</span>
                  <span>{f.artifactName}</span>
                  <span>·</span>
                  <span>{f.agent}</span>
                </div>
                <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{f.detail}</p>
                <div className="mt-3 overflow-x-auto rounded-md border border-border bg-background p-3">
                  <code className="font-mono text-xs text-sev-high">{f.evidence}</code>
                </div>
                <p className="mt-2 font-mono text-[11px] text-muted-foreground">{f.location}</p>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

/* ----------------------------- Drift ----------------------------- */

function DriftPanel({ artifacts: rows }: { artifacts: Artifact[] }) {
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-10 text-center">
        <p className="font-mono text-sm text-ok">No drift detected</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Every artifact on disk matches its locked, audited hash.
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        These artifacts changed on disk after they were audited, or were never signed. A drifted
        hash is the rug-pull signal: what runs today is not what you approved.
      </p>
      {rows.map((a) => (
        <div key={a.id} className="rounded-lg border border-border bg-card p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <FileCode2 className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-sm font-medium text-foreground">{a.name}</span>
              <span className="font-mono text-xs text-muted-foreground">
                {a.agent} · v{a.version}
              </span>
            </div>
            <DriftBadge status={a.drift} />
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            <div className="rounded-md border border-border bg-background p-3">
              <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
                Locked (audited)
              </p>
              <p className="mt-1 font-mono text-xs text-ok">{a.lockedHash ?? "— never signed —"}</p>
            </div>
            <div className="rounded-md border border-sev-critical/30 bg-sev-critical/5 p-3">
              <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
                On disk now
              </p>
              <p className="mt-1 font-mono text-xs text-sev-critical">{a.hash}</p>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
