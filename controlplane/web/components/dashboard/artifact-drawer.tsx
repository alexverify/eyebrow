"use client"

import { useEffect, useState } from "react"
import { X, FileCode2, ShieldCheck, ShieldAlert, Network, FolderTree, Terminal } from "lucide-react"
import { cn } from "@/lib/utils"
import { KIND_LABELS, PATTERN_LABELS, type Artifact } from "@/lib/scan-data"
import { SeverityBadge, DriftBadge, VerdictBadge } from "@/components/dashboard/badges"
import { runAction, type ActionKind } from "@/lib/actions"

interface AuditEvent {
  ts: string
  server: string
  kind: string
  tool?: string
  host?: string
  status?: string
  detail?: string
}

/**
 * ArtifactDrawer is the per-artifact security profile: a slide-over panel
 * showing provenance, integrity, capabilities, findings, the file manifest,
 * and — for wrapped MCP servers — the live audit activity.
 */
export function ArtifactDrawer({
  artifact,
  onClose,
  live = false,
  onChanged,
}: {
  artifact: Artifact | null
  onClose: () => void
  live?: boolean
  onChanged?: () => void
}) {
  const open = artifact !== null

  // Close on Escape.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open, onClose])

  return (
    <>
      <div
        className={cn(
          "fixed inset-0 z-40 bg-background/70 backdrop-blur-sm transition-opacity",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        onClick={onClose}
        aria-hidden
      />
      <aside
        className={cn(
          "fixed right-0 top-0 z-50 flex h-full w-full max-w-[560px] flex-col border-l border-border bg-card shadow-xl transition-transform",
          open ? "translate-x-0" : "translate-x-full",
        )}
        aria-hidden={!open}
      >
        {artifact && <DrawerBody artifact={artifact} onClose={onClose} live={live} onChanged={onChanged} />}
      </aside>
    </>
  )
}

function DrawerBody({
  artifact: a,
  onClose,
  live,
  onChanged,
}: {
  artifact: Artifact
  onClose: () => void
  live: boolean
  onChanged?: () => void
}) {
  return (
    <>
      <header className="flex items-start justify-between gap-4 border-b border-border px-6 py-4">
        <div className="flex items-center gap-2.5">
          <FileCode2 className="h-5 w-5 shrink-0 text-muted-foreground" />
          <div className="min-w-0">
            <p className="truncate font-mono text-sm font-semibold text-foreground">{a.name}</p>
            <p className="text-xs text-muted-foreground">
              {KIND_LABELS[a.kind] ?? a.kind} · {a.agent}
              {a.version ? ` · v${a.version}` : ""}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <DriftBadge status={a.drift} />
          <button
            onClick={onClose}
            aria-label="Close"
            className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-6 py-5">
        {live ? <Actions a={a} onChanged={onChanged} /> : null}
        <Trust a={a} />
        <ProvenanceLadder a={a} />
        <Provenance a={a} />
        <Integrity a={a} />
        <Capabilities a={a} />
        <Findings a={a} />
        <FileManifest a={a} />
        {a.kind === "mcp" && <Activity name={a.name} />}
      </div>
    </>
  )
}

/* ----------------------------- Sections ----------------------------- */

function Section({ icon: Icon, title, children }: { icon?: typeof ShieldCheck; title: string; children: React.ReactNode }) {
  return (
    <section className="mb-6">
      <h3 className="mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
        {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
        {title}
      </h3>
      {children}
    </section>
  )
}

function Row({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  if (!value) return null
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-border/60 py-1.5 last:border-0">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={cn("truncate text-right text-xs text-foreground", mono && "font-mono")}>{value}</span>
    </div>
  )
}

function Actions({ a, onChanged }: { a: Artifact; onChanged?: () => void }) {
  const [busy, setBusy] = useState<ActionKind | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = (kind: ActionKind, on: boolean) => {
    setBusy(kind)
    setError(null)
    runAction(kind, a.id, on)
      .then(() => onChanged?.())
      .catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => setBusy(null))
  }

  const btn =
    "inline-flex items-center justify-center rounded-md border px-3 py-1.5 font-mono text-xs transition-colors disabled:opacity-50"

  return (
    <section className="mb-6">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => run("approve", true)}
          className={cn(btn, "border-ok/40 text-ok hover:bg-ok/10")}
        >
          {busy === "approve" ? "…" : "Approve"}
        </button>
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => run("quarantine", !a.quarantined)}
          className={cn(btn, "border-sev-critical/40 text-sev-critical hover:bg-sev-critical/10")}
        >
          {busy === "quarantine" ? "…" : a.quarantined ? "Lift quarantine" : "Quarantine"}
        </button>
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => run("freeze", !a.frozen)}
          className={cn(btn, "border-border text-muted-foreground hover:bg-muted/40 hover:text-foreground")}
        >
          {busy === "freeze" ? "…" : a.frozen ? "Unfreeze" : "Freeze"}
        </button>
      </div>
      {error ? <p className="mt-2 font-mono text-[11px] text-sev-critical">{error}</p> : null}
    </section>
  )
}

function Trust({ a }: { a: Artifact }) {
  if (a.verdict === undefined) return null
  return (
    <Section icon={ShieldAlert} title="Trust">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <VerdictBadge verdict={a.verdict} score={a.trust} />
          {a.quarantined ? (
            <span className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-2 py-0.5 font-mono text-[11px] text-sev-critical">
              quarantined
            </span>
          ) : null}
          {a.frozen ? (
            <span className="rounded-md border border-border bg-muted/40 px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
              frozen
            </span>
          ) : null}
        </div>
        {a.driftDetail ? <span className="text-xs text-muted-foreground">{a.driftDetail}</span> : null}
      </div>
      {a.trustReasons && a.trustReasons.length > 0 ? (
        <div className="mt-3 rounded-md border border-border bg-background p-3">
          <p className="mb-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">Score breakdown</p>
          <div className="flex flex-col gap-1">
            <div className="flex items-baseline justify-between font-mono text-xs">
              <span className="text-muted-foreground">base</span>
              <span className="tabular-nums text-foreground">100</span>
            </div>
            {a.trustReasons.map((r, i) => (
              <div key={i} className="flex items-baseline justify-between gap-4 font-mono text-xs">
                <span className="truncate text-muted-foreground">{r.label}</span>
                <span className={cn("shrink-0 tabular-nums", r.delta < 0 ? "text-sev-high" : "text-ok")}>
                  {r.delta > 0 ? `+${r.delta}` : r.delta}
                </span>
              </div>
            ))}
            <div className="mt-1 flex items-baseline justify-between border-t border-border/60 pt-1 font-mono text-xs">
              <span className="text-foreground">trust</span>
              <span className="tabular-nums text-foreground">{a.trust}</span>
            </div>
          </div>
        </div>
      ) : null}
    </Section>
  )
}

function ProvenanceLadder({ a }: { a: Artifact }) {
  const p = a.provenance
  if (!p || !p.rungs) return null
  return (
    <Section icon={ShieldCheck} title={`Provenance — level ${p.level} / ${p.max}`}>
      <div className="flex flex-col gap-1">
        {p.rungs.map((r, i) => (
          <div key={i} className="flex items-center gap-2 font-mono text-xs">
            <span className={cn("text-sm leading-none", r.ok ? "text-ok" : "text-muted-foreground")}>
              {r.ok ? "✓" : "○"}
            </span>
            <span className={cn(r.ok ? "text-foreground" : "text-muted-foreground")}>{r.label}</span>
          </div>
        ))}
      </div>
    </Section>
  )
}

function Provenance({ a }: { a: Artifact }) {
  return (
    <Section title="Provenance">
      <Row label="Source" value={a.source} mono />
      <Row label="Type" value={a.sourceKind} />
      <Row label="Scope" value={a.scope} mono />
      <Row label="Discovered from" value={a.discoveredFrom} mono />
      {a.command ? (
        <div className="mt-2 rounded-md border border-border bg-background p-2.5">
          <p className="mb-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <Terminal className="h-3 w-3" /> Launch command
          </p>
          <code className="font-mono text-xs text-foreground break-all">
            {[a.command, ...(a.args ?? [])].join(" ")}
          </code>
          {a.envKeys && a.envKeys.length > 0 ? (
            <p className="mt-2 text-[11px] text-muted-foreground">
              env: <span className="font-mono text-foreground">{a.envKeys.join(", ")}</span> (values hidden)
            </p>
          ) : null}
        </div>
      ) : null}
    </Section>
  )
}

function Integrity({ a }: { a: Artifact }) {
  const moved = a.lockedHash && a.hash && a.lockedHash !== a.hash
  return (
    <Section icon={ShieldCheck} title="Integrity">
      <Row label="Installed" value={a.installedAt} mono />
      <Row label="npm integrity" value={a.integrity} mono />
      <Row label="TLS pin" value={a.certSpki} mono />
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        <div className="rounded-md border border-border bg-background p-2.5">
          <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Locked</p>
          <p className="mt-1 font-mono text-xs text-ok break-all">{a.lockedHash ?? "— never signed —"}</p>
        </div>
        <div
          className={cn(
            "rounded-md border bg-background p-2.5",
            moved ? "border-sev-critical/40" : "border-border",
          )}
        >
          <p className="text-[11px] uppercase tracking-wide text-muted-foreground">On disk now</p>
          <p className={cn("mt-1 font-mono text-xs break-all", moved ? "text-sev-critical" : "text-foreground")}>
            {a.hash}
          </p>
        </div>
      </div>
      {a.approval ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Approved by <span className="text-foreground">{a.approval.by ?? "—"}</span>
          {a.approval.at ? ` on ${a.approval.at}` : ""} ·{" "}
          {a.approval.signed ? <span className="text-ok">signed</span> : <span className="text-sev-high">unsigned</span>}
        </p>
      ) : null}
    </Section>
  )
}

function Capabilities({ a }: { a: Artifact }) {
  const c = a.capabilities
  if (!c) return null
  const none = !c.exec && c.network.length === 0 && c.filesystem.length === 0
  const expanded =
    c.execNewlyAdded || (c.addedNetwork?.length ?? 0) > 0 || (c.addedFilesystem?.length ?? 0) > 0
  return (
    <Section icon={Network} title="Capabilities">
      {expanded ? (
        <div className="mb-3 rounded-md border border-sev-high/30 bg-sev-high/5 p-2.5 text-xs text-sev-high">
          Capability expansion since the locked version:
          <ul className="mt-1 list-inside list-disc font-mono text-[11px]">
            {c.execNewlyAdded ? <li>now executes commands</li> : null}
            {(c.addedNetwork ?? []).map((h) => (
              <li key={`n-${h}`}>+ network: {h}</li>
            ))}
            {(c.addedFilesystem ?? []).map((p) => (
              <li key={`f-${p}`}>
                + filesystem: {p}
                {(c.sensitiveAdded ?? []).includes(p) ? " ⚠ secret path" : ""}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {none ? (
        <p className="text-xs text-muted-foreground">No declared exec, network, or filesystem capabilities.</p>
      ) : (
        <div className="flex flex-col gap-1.5">
          <Row label="Executes commands" value={c.exec ? "yes" : "no"} />
          {c.network.length > 0 ? <Row label="Network" value={c.network.join(", ")} mono /> : null}
          {c.filesystem.length > 0 ? <Row label="Filesystem" value={c.filesystem.join(", ")} mono /> : null}
        </div>
      )}
    </Section>
  )
}

function Findings({ a }: { a: Artifact }) {
  if (a.findings.length === 0) {
    return (
      <Section title="Findings">
        <p className="text-xs text-ok">No security findings.</p>
      </Section>
    )
  }
  return (
    <Section title={`Findings (${a.findings.length})`}>
      <div className="flex flex-col gap-2">
        {a.findings.map((f) => (
          <div key={f.id} className="rounded-md border border-border bg-background p-3">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <span className="min-w-0 flex-1 truncate text-sm text-foreground">{f.title}</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{f.detail}</p>
            {f.evidence ? (
              <code className="mt-2 block overflow-x-auto rounded border border-border bg-card p-2 font-mono text-xs text-sev-high">
                {f.evidence}
              </code>
            ) : null}
            <p className="mt-1.5 font-mono text-[11px] text-muted-foreground">
              {PATTERN_LABELS[f.pattern] ?? f.pattern}
              {f.location ? ` · ${f.location}` : ""}
              {f.owasp ? ` · ${f.owasp}` : ""}
            </p>
          </div>
        ))}
      </div>
    </Section>
  )
}

function FileManifest({ a }: { a: Artifact }) {
  const files = a.files ?? []
  if (files.length === 0) return null
  return (
    <Section icon={FolderTree} title={`File manifest (${files.length})`}>
      <details className="rounded-md border border-border bg-background">
        <summary className="cursor-pointer px-3 py-2 text-xs text-muted-foreground">
          Show {files.length} files
        </summary>
        <div className="border-t border-border">
          {files.map((f) => (
            <div key={f.path} className="flex items-baseline justify-between gap-4 px-3 py-1.5 font-mono text-[11px]">
              <span className="truncate text-foreground">{f.path}</span>
              <span className="shrink-0 text-muted-foreground">{f.hash.slice(0, 12)}</span>
            </div>
          ))}
        </div>
      </details>
    </Section>
  )
}

function Activity({ name }: { name: string }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null)
  useEffect(() => {
    let cancelled = false
    fetch(`/api/audit?server=${encodeURIComponent(name)}`)
      .then((r) => (r.ok ? r.json() : { events: [] }))
      .then((d: { events?: AuditEvent[] }) => !cancelled && setEvents(d.events ?? []))
      .catch(() => !cancelled && setEvents([]))
    return () => {
      cancelled = true
    }
  }, [name])

  return (
    <Section title="Runtime activity">
      {events === null ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : events.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No audit events. Wrap this server with <span className="font-mono">agentguard wrap</span> to record tool
          calls and egress.
        </p>
      ) : (
        <div className="flex flex-col">
          {events.slice(-50).reverse().map((e, i) => (
            <div key={`${e.ts}-${i}`} className="flex items-baseline justify-between gap-3 border-b border-border/60 py-1.5 font-mono text-[11px] last:border-0">
              <span className="text-muted-foreground">{e.ts?.replace("T", " ").replace("Z", "")}</span>
              <span className="flex-1 truncate text-foreground">{e.kind} {e.tool || e.host || ""}</span>
              <span className={cn(e.status === "denied" ? "text-sev-critical" : "text-ok")}>{e.status}</span>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}
