"use client"

import { useEffect, useMemo, useState } from "react"
import {
  Search,
  Boxes,
  ShieldAlert,
  GitCompareArrows,
  FileCode2,
  ChevronRight,
  Terminal,
  Inbox,
  Activity as ActivityIcon,
  AlertTriangle,
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
  driftCounts,
  topSeverity,
  verdictCounts,
  SEVERITY_STYLES,
} from "@/lib/scan-utils"
import { useScan } from "@/lib/use-scan"
import { StatCard } from "@/components/dashboard/stat-card"
import { SeverityBadge, DriftBadge, VerdictBadge } from "@/components/dashboard/badges"
import { ArtifactDrawer } from "@/components/dashboard/artifact-drawer"

type TabId = "changes" | "inventory" | "findings" | "drift" | "activity"

const TABS: { id: TabId; label: string; icon: typeof Boxes }[] = [
  { id: "changes", label: "Changes", icon: Inbox },
  { id: "inventory", label: "Inventory & Lockfile", icon: Boxes },
  { id: "findings", label: "Security Findings", icon: ShieldAlert },
  { id: "drift", label: "Rug-pull / Drift", icon: GitCompareArrows },
  { id: "activity", label: "Activity", icon: ActivityIcon },
]

export function Dashboard() {
  const { artifacts, loading, live, reload } = useScan()
  const [tab, setTab] = useState<TabId>("changes")
  const [query, setQuery] = useState("")
  const [agentFilter, setAgentFilter] = useState<Agent | "all">("all")
  const [kindFilter, setKindFilter] = useState<ArtifactKind | "all">("all")
  const [selected, setSelected] = useState<Artifact | null>(null)

  const drift = useMemo(() => driftCounts(artifacts), [artifacts])
  const verdicts = useMemo(() => verdictCounts(artifacts), [artifacts])
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

  const updatedArtifacts = useMemo(
    () => artifacts.filter((a) => a.drift === "updated"),
    [artifacts],
  )

  // "What changed since I last looked": anything not in its audited steady
  // state — newly discovered, updated, or drifted.
  const changedArtifacts = useMemo(
    () => artifacts.filter((a) => a.drift === "drifted" || a.drift === "new" || a.drift === "updated"),
    [artifacts],
  )

  // Known-malicious matches (B2) carry an ADVISORY-* finding; surface them as a
  // top-level banner regardless of which tab is open.
  const advisories = useMemo(
    () => artifacts.filter((a) => a.findings.some((f) => (f.ruleId ?? "").startsWith("ADVISORY"))),
    [artifacts],
  )

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
          <span className="text-foreground">npx assay scan</span>
        </div>
      </div>

      {/* Known-malicious banner (B2) */}
      {advisories.length > 0 && (
        <div className="mt-6 flex items-start gap-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-sev-critical" />
          <div className="text-sm">
            <p className="font-medium text-sev-critical">
              {advisories.length} artifact{advisories.length > 1 ? "s" : ""} match a known-malicious advisory
            </p>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground">
              {advisories.map((a) => a.name).join(", ")} — quarantine and remove immediately.
            </p>
          </div>
        </div>
      )}

      {/* Summary stats */}
      <div className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Quarantine"
          value={verdicts.quarantine}
          hint="recommend disabling"
          accent={verdicts.quarantine > 0 ? "critical" : "ok"}
        />
        <StatCard
          label="Review"
          value={verdicts.review}
          hint="changed or unproven"
          accent={verdicts.review > 0 ? "high" : "ok"}
        />
        <StatCard
          label="Drifted"
          value={driftedCount}
          hint="changed since audit"
          accent={driftedCount > 0 ? "critical" : "ok"}
        />
        <StatCard label="Trusted" value={verdicts.trusted} hint="match audit, verifiable" accent="ok" />
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
        {tab === "changes" && <ChangesPanel artifacts={changedArtifacts} onSelect={setSelected} />}
        {tab === "activity" && <ActivityPanel />}
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
            onSelect={setSelected}
          />
        )}
        {tab === "findings" && <FindingsPanel findings={findings} />}
        {tab === "drift" && <DriftPanel drifted={driftedArtifacts} updated={updatedArtifacts} />}
      </div>

      <ArtifactDrawer
        artifact={selected}
        live={live}
        onClose={() => setSelected(null)}
        onChanged={() => {
          reload()
          setSelected(null)
        }}
      />
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
  onSelect,
}: {
  artifacts: Artifact[]
  agents: Agent[]
  query: string
  setQuery: (v: string) => void
  agentFilter: Agent | "all"
  setAgentFilter: (v: Agent | "all") => void
  kindFilter: ArtifactKind | "all"
  setKindFilter: (v: ArtifactKind | "all") => void
  onSelect: (a: Artifact) => void
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
        <div className="hidden grid-cols-[1.5fr_0.6fr_0.7fr_1.1fr_0.9fr_0.9fr_0.6fr] gap-4 border-b border-border bg-muted/40 px-4 py-2.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground md:grid">
          <span>Artifact</span>
          <span>Type</span>
          <span>Agent</span>
          <span>Trust</span>
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
              <button
                key={a.id}
                type="button"
                onClick={() => onSelect(a)}
                className="grid w-full grid-cols-1 gap-2 border-b border-border px-4 py-3 text-left last:border-0 transition-colors hover:bg-muted/30 md:grid-cols-[1.5fr_0.6fr_0.7fr_1.1fr_0.9fr_0.9fr_0.6fr] md:items-center md:gap-4"
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
                <span>{a.verdict ? <VerdictBadge verdict={a.verdict} score={a.trust} /> : null}</span>
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
              </button>
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

function DriftPanel({ drifted: rows, updated }: { drifted: Artifact[]; updated: Artifact[] }) {
  if (rows.length === 0 && updated.length === 0) {
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
    <div className="flex flex-col gap-6">
      {updated.length > 0 && (
        <div>
          <p className="mb-2 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
            Updated (expected) — {updated.length}
          </p>
          <div className="flex flex-col gap-2">
            {updated.map((a) => (
              <div
                key={a.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-card px-4 py-3"
              >
                <div className="flex items-center gap-2.5">
                  <FileCode2 className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono text-sm font-medium text-foreground">{a.name}</span>
                  <span className="text-xs text-muted-foreground">{a.driftDetail}</span>
                </div>
                <DriftBadge status={a.drift} />
              </div>
            ))}
          </div>
        </div>
      )}
      {rows.length > 0 && (
        <div>
          <p className="mb-2 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
            Drifted (unexpected) — {rows.length}
          </p>
          <p className="mb-3 text-sm text-muted-foreground">
            These artifacts changed on disk after they were audited, or were never signed. A drifted
            hash is the rug-pull signal: what runs today is not what you approved.
          </p>
          <div className="flex flex-col gap-3">
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
                {a.driftDetail ? (
                  <p className="mt-2 text-xs text-sev-critical">{a.driftDetail}</p>
                ) : null}
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
        </div>
      )}
    </div>
  )
}

/* ----------------------------- Changes ----------------------------- */

function ChangesPanel({
  artifacts: rows,
  onSelect,
}: {
  artifacts: Artifact[]
  onSelect: (a: Artifact) => void
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-10 text-center">
        <p className="font-mono text-sm text-ok">Nothing changed since you last looked</p>
        <p className="mt-1 text-sm text-muted-foreground">
          No new, updated, or drifted artifacts. Run <span className="font-mono">assay digest</span> for
          the same summary in your terminal or CI.
        </p>
      </div>
    )
  }
  // Loudest first: drifted, then new, then updated.
  const order: Record<string, number> = { drifted: 0, new: 1, updated: 2, unsigned: 3, verified: 4 }
  const sorted = [...rows].sort((a, b) => (order[a.drift] ?? 9) - (order[b.drift] ?? 9))
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">
        {rows.length} artifact{rows.length > 1 ? "s" : ""} to review since the lockfile.
      </p>
      {sorted.map((a) => (
        <button
          key={a.id}
          type="button"
          onClick={() => onSelect(a)}
          className="flex w-full flex-col gap-1.5 rounded-lg border border-border bg-card px-4 py-3 text-left transition-colors hover:bg-muted/30"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <FileCode2 className="h-4 w-4 shrink-0 text-muted-foreground" />
              <span className="font-mono text-sm font-medium text-foreground">{a.name}</span>
              <span className="font-mono text-xs text-muted-foreground">
                {a.agent} · {a.kind}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {a.verdict ? <VerdictBadge verdict={a.verdict} score={a.trust} /> : null}
              <DriftBadge status={a.drift} />
            </div>
          </div>
          {a.driftDetail ? (
            <p className={cn("text-xs", a.drift === "drifted" ? "text-sev-critical" : "text-muted-foreground")}>
              {a.driftDetail}
            </p>
          ) : null}
        </button>
      ))}
    </div>
  )
}

/* ----------------------------- Activity ----------------------------- */

interface ActivityEvent {
  ts: string
  server: string
  kind: string
  tool?: string
  host?: string
  status?: string
  bytesUp?: number
  bytesDown?: number
  redactions?: number
}

interface ActivitySummary {
  total: number
  toolCalls: number
  denied: number
  egress: number
  redactions: number
}

function EgressMap({ events }: { events: ActivityEvent[] }) {
  const rows = useMemo(() => {
    const byHost = new Map<
      string,
      { host: string; up: number; down: number; redactions: number; servers: Set<string>; count: number }
    >()
    for (const e of events) {
      if (e.kind !== "egress" || !e.host) continue
      const r =
        byHost.get(e.host) ??
        { host: e.host, up: 0, down: 0, redactions: 0, servers: new Set<string>(), count: 0 }
      r.up += e.bytesUp ?? 0
      r.down += e.bytesDown ?? 0
      r.redactions += e.redactions ?? 0
      r.count += 1
      if (e.server) r.servers.add(e.server)
      byHost.set(e.host, r)
    }
    return Array.from(byHost.values()).sort((a, b) => b.count - a.count)
  }, [events])

  if (rows.length === 0) return null
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="border-b border-border bg-muted/40 px-4 py-2 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
        Egress map — {rows.length} host{rows.length > 1 ? "s" : ""} contacted
      </div>
      {rows.map((r) => (
        <div
          key={r.host}
          className="grid grid-cols-[1.4fr_1fr_auto] items-baseline gap-3 border-b border-border/60 px-4 py-1.5 font-mono text-[11px] last:border-0"
        >
          <span className="truncate text-foreground">{r.host}</span>
          <span className="truncate text-muted-foreground">{Array.from(r.servers).join(", ")}</span>
          <span className="text-muted-foreground">
            ↑{r.up} ↓{r.down}
            {r.redactions ? ` · ${r.redactions} redacted` : ""} · {r.count}×
          </span>
        </div>
      ))}
    </div>
  )
}

function ActivityPanel() {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null)
  const [summary, setSummary] = useState<ActivitySummary | null>(null)

  useEffect(() => {
    let cancelled = false
    fetch("/api/audit")
      .then((r) => (r.ok ? r.json() : { events: [], summary: null }))
      .then((d: { events?: ActivityEvent[]; summary?: ActivitySummary }) => {
        if (cancelled) return
        setEvents(d.events ?? [])
        setSummary(d.summary ?? null)
      })
      .catch(() => !cancelled && setEvents([]))
    return () => {
      cancelled = true
    }
  }, [])

  if (events === null) {
    return <p className="text-sm text-muted-foreground">Loading activity…</p>
  }
  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-10 text-center">
        <p className="font-mono text-sm text-muted-foreground">No runtime activity recorded</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Wrap a tool's MCP servers with <span className="font-mono">assay wrap</span> to audit every tool
          call and outbound connection here.
        </p>
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-4">
      {summary ? (
        <p className="font-mono text-xs text-muted-foreground">
          {summary.total} events · {summary.toolCalls} tool calls · {summary.denied} denied · {summary.egress}{" "}
          egress · {summary.redactions} redactions
        </p>
      ) : null}
      <EgressMap events={events} />
      <div className="overflow-hidden rounded-lg border border-border">
        {events
          .slice(-200)
          .reverse()
          .map((e, i) => (
            <div
              key={`${e.ts}-${i}`}
              className="grid grid-cols-[auto_1fr_auto] items-baseline gap-3 border-b border-border/60 px-4 py-1.5 font-mono text-[11px] last:border-0"
            >
              <span className="text-muted-foreground">{e.ts?.replace("T", " ").replace("Z", "")}</span>
              <span className="truncate text-foreground">
                <span className="text-muted-foreground">{e.server}</span> {e.kind}{" "}
                {e.tool || e.host || ""}
                {e.kind === "egress" && (e.bytesUp || e.bytesDown)
                  ? ` (↑${e.bytesUp ?? 0} ↓${e.bytesDown ?? 0}${e.redactions ? `, ${e.redactions} redacted` : ""})`
                  : ""}
              </span>
              <span className={cn(e.status === "denied" ? "text-sev-critical" : "text-ok")}>{e.status}</span>
            </div>
          ))}
      </div>
    </div>
  )
}
