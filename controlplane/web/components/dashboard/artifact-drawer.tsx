"use client"

import { useEffect, useState } from "react"
import { X, FileCode2, ShieldCheck, ShieldAlert, Network, FolderTree, Terminal, EyeOff, GitCompareArrows, Clock, AlarmClock, History } from "lucide-react"
import { cn } from "@/lib/utils"
import { KIND_LABELS, PATTERN_LABELS, type Artifact, type LineDiff } from "@/lib/scan-data"
import { SeverityBadge, DriftBadge, VerdictBadge, LivenessBadge, ReachBadge, ReputationBadge } from "@/components/dashboard/badges"
import { runAction, muteFinding, allowEgress, type ActionKind } from "@/lib/actions"
import { type CodeTarget } from "@/components/dashboard/code-view"

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
  onViewSource,
}: {
  artifact: Artifact | null
  onClose: () => void
  live?: boolean
  onChanged?: () => void
  onViewSource?: (t: CodeTarget) => void
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
        {artifact && (
          <DrawerBody
            artifact={artifact}
            onClose={onClose}
            live={live}
            onChanged={onChanged}
            onViewSource={onViewSource}
          />
        )}
      </aside>
    </>
  )
}

function DrawerBody({
  artifact: a,
  onClose,
  live,
  onChanged,
  onViewSource,
}: {
  artifact: Artifact
  onClose: () => void
  live: boolean
  onChanged?: () => void
  onViewSource?: (t: CodeTarget) => void
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
          {a.shadow ? (
            <span className="inline-flex items-center gap-1 rounded-md border border-sev-high/40 bg-sev-high/10 px-2 py-0.5 font-mono text-[11px] text-sev-high">
              <EyeOff className="h-3 w-3" /> unaccounted
            </span>
          ) : null}
          <DriftBadge status={a.drift} approved={a.approval?.status === "approved"} />
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
        <SleeperBanner a={a} />
        {live ? <Actions a={a} onChanged={onChanged} /> : null}
        <Trust a={a} />
        <ProvenanceLadder a={a} />
        <Provenance a={a} />
        <Integrity a={a} />
        <Timeline a={a} />
        <Usage a={a} />
        <ChangedFiles a={a} />
        <Capabilities a={a} />
        <Findings a={a} live={live} onChanged={onChanged} onViewSource={onViewSource} />
        <FileManifest a={a} />
        {a.kind === "mcp" && <Activity name={a.name} live={live} />}
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
        <div className="flex items-center gap-2">
          <ReputationBadge reputation={a.reputation} />
          {a.driftDetail ? <span className="text-xs text-muted-foreground">{a.driftDetail}</span> : null}
        </div>
      </div>
      {a.reputation && a.reputation.grade !== "unknown" && a.reputation.trusters > 0 ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Community: this exact hash is trusted by{" "}
          <span className="text-foreground">{a.reputation.trusters}</span> other assay user
          {a.reputation.trusters === 1 ? "" : "s"}
          {a.reputation.firstSeen ? `, first seen ${a.reputation.firstSeen}` : ""}. Hash-only, opt-in — no
          code or identity leaves your machine.
        </p>
      ) : null}
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

// SleeperBanner surfaces the dormant-then-active finding (F2) at the very top of
// the profile, because it is the single highest-signal supply-chain event assay
// can catch: an artifact that sat unused for weeks, drifted, then ran for the
// first time. The triple (old install × content drift × first-ever invocation)
// is invisible to a pure static scanner.
function SleeperBanner({ a }: { a: Artifact }) {
  if (!a.sleeper) return null
  return (
    <div className="mb-5 rounded-md border border-sev-critical/50 bg-sev-critical/10 p-3">
      <p className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-sev-critical">
        <AlarmClock className="h-3.5 w-3.5" /> Sleeper — dormant then active
      </p>
      <p className="mt-1.5 text-xs leading-relaxed text-foreground">{a.sleeper.detail}</p>
    </div>
  )
}

// dotColor maps a timeline severity onto the dashboard color tokens.
const dotColor: Record<string, string> = {
  ok: "bg-ok",
  info: "bg-muted-foreground",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
}

// Timeline renders the per-artifact event ribbon (F4): the unified "what
// happened, when" history — installed → approved → invoked → drifted — that a
// reviewer wants in an incident, where the rest of the drawer shows only
// current state. Built server-side from dated facts; shown when any exist.
function Timeline({ a }: { a: Artifact }) {
  const events = a.timeline ?? []
  if (events.length === 0) return null
  return (
    <Section icon={History} title="Timeline">
      <ol className="relative ml-1.5 border-l border-border">
        {events.map((e, i) => (
          <li key={`${e.kind}-${i}`} className="relative ml-4 pb-4 last:pb-0">
            <span
              className={cn(
                "absolute -left-[1.4rem] top-1 h-2.5 w-2.5 rounded-full ring-2 ring-card",
                dotColor[e.severity] ?? "bg-muted-foreground",
              )}
              aria-hidden
            />
            <div className="flex items-baseline justify-between gap-3">
              <span
                className={cn(
                  "text-xs font-medium",
                  e.severity === "critical"
                    ? "text-sev-critical"
                    : e.severity === "high"
                      ? "text-sev-high"
                      : e.severity === "ok"
                        ? "text-ok"
                        : "text-foreground",
                )}
              >
                {e.label}
              </span>
              <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{e.at}</span>
            </div>
            {e.detail ? <p className="mt-0.5 text-[11px] text-muted-foreground">{e.detail}</p> : null}
          </li>
        ))}
      </ol>
    </Section>
  )
}

// Usage renders runtime invocation telemetry (F1): when this artifact last and
// first ran, and how often. Today the only telemetry source is the MCP shim's
// audit log, so usage appears for wrapped MCP servers that have actually run;
// for everything else there is no usage signal yet, and we say so plainly rather
// than implying "never used."
function Usage({ a }: { a: Artifact }) {
  const u = a.usage
  if (a.kind !== "mcp") return null
  return (
    <Section icon={Clock} title="Usage">
      {u ? (
        <>
          <div className="mb-2 flex items-baseline gap-2">
            <span className="font-mono text-lg tabular-nums text-foreground">{u.count.toLocaleString()}</span>
            <span className="text-xs text-muted-foreground">
              invocation{u.count === 1 ? "" : "s"} recorded
              {u.lastUsedRel ? ` · last ${u.lastUsedRel}` : ""}
            </span>
          </div>
          <Row label="First used" value={u.firstUsed} mono />
          <Row label="Last used" value={u.lastUsed} mono />
        </>
      ) : (
        <p className="text-xs text-muted-foreground">
          No invocations recorded. Wrap this server with <span className="font-mono">assay wrap</span> to
          capture when it runs.
        </p>
      )}
    </Section>
  )
}

// ChangedFiles renders the file-manifest diff (H1): exactly which files were
// added / removed / modified since the locked, audited snapshot. When the local
// blob store holds the approved and current bytes, each file expands to its
// literal line-level diff (H1b) — the actual `+ exfiltrate(wallet)` line, not
// just the file name. Degrades to the content-free name list when no baseline
// is stored. Shown only when a drift actually moved files.
function ChangedFiles({ a }: { a: Artifact }) {
  const d = a.fileChanges
  if (!d) return null
  const added = d.added ?? []
  const removed = d.removed ?? []
  const modified = d.modified ?? []
  const total = added.length + removed.length + modified.length
  if (total === 0) return null

  const byPath = new Map((a.lineDiffs ?? []).map((ld) => [ld.path, ld]))
  const haveLines = byPath.size > 0

  return (
    <Section icon={GitCompareArrows} title={`Changed files (${total})`}>
      <p className="mb-2 text-xs text-muted-foreground">
        {haveLines
          ? "What changed on disk since the locked snapshot — expanded to the exact lines added and removed."
          : "What moved on disk since the locked snapshot. The exact files that changed are named here — the rug-pull surface."}
      </p>
      <div className="overflow-hidden rounded-md border border-border bg-background font-mono text-[11px]">
        {modified.map((p) => (
          <FileChangeBlock key={`m-${p}`} sigil="~" path={p} className="text-sev-high" diff={byPath.get(p)} />
        ))}
        {added.map((p) => (
          <FileChangeBlock key={`a-${p}`} sigil="+" path={p} className="text-sev-critical" diff={byPath.get(p)} />
        ))}
        {removed.map((p) => (
          <FileChangeBlock
            key={`r-${p}`}
            sigil="−"
            path={p}
            className="text-muted-foreground line-through"
            diff={byPath.get(p)}
          />
        ))}
      </div>
    </Section>
  )
}

function FileChangeBlock({
  sigil,
  path,
  className,
  diff,
}: {
  sigil: string
  path: string
  className: string
  diff?: LineDiff
}) {
  return (
    <div className="border-b border-border/60 last:border-0">
      <div className="flex items-baseline gap-2 px-3 py-1.5">
        <span className={cn("w-3 shrink-0 text-center", className)}>{sigil}</span>
        <span className={cn("truncate", className)}>{path}</span>
        {diff ? (
          <span className="ml-auto shrink-0 text-[10px] text-muted-foreground">
            <span className="text-sev-critical">+{diff.added}</span>{" "}
            <span>−{diff.removed}</span>
          </span>
        ) : null}
      </div>
      {diff ? <DiffHunks diff={diff} /> : null}
    </div>
  )
}

// DiffHunks renders the unified line-level diff for one file (H1b): context
// lines plain, additions green, removals struck through, each hunk headed by its
// `@@` range so a reviewer can place the change in the file.
function DiffHunks({ diff }: { diff: LineDiff }) {
  return (
    <div className="border-t border-border/60 bg-muted/20">
      {diff.hunks.map((h, hi) => (
        <div key={hi} className="border-b border-border/40 last:border-0">
          <div className="bg-muted/40 px-3 py-0.5 text-[10px] text-muted-foreground">
            @@ -{h.oldStart},{h.oldCount} +{h.newStart},{h.newCount} @@
          </div>
          {h.lines.map((l, li) => (
            <div
              key={li}
              className={cn(
                "flex gap-2 whitespace-pre-wrap break-all px-3",
                l.op === "+" && "bg-sev-critical/10 text-sev-critical",
                l.op === "-" && "bg-muted/50 text-muted-foreground",
              )}
            >
              <span className="w-3 shrink-0 select-none text-center text-muted-foreground">
                {l.op === " " ? "" : l.op}
              </span>
              <span>{l.text === "" ? " " : l.text}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
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

function Findings({
  a,
  live,
  onChanged,
  onViewSource,
}: {
  a: Artifact
  live: boolean
  onChanged?: () => void
  onViewSource?: (t: CodeTarget) => void
}) {
  // All findings on the same file, so the code view can mark every flagged line.
  const highlightsFor = (file: string) =>
    a.findings
      .filter((f) => f.file === file)
      .map((f) => ({
        line: f.line ?? 0,
        title: f.title,
        severity: f.severity,
        snippet: f.evidence,
        ruleId: f.ruleId,
        owasp: f.owasp,
        detail: f.detail,
      }))
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
              <LivenessBadge liveness={f.liveness} />
              <ReachBadge reach={f.reach} />
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
              {f.file && onViewSource ? (
                <>
                  {" · "}
                  <button
                    type="button"
                    onClick={() =>
                      onViewSource({
                        artifactId: a.id,
                        file: f.file!,
                        focusLine: f.line,
                        artifact: { name: a.name, kind: a.kind, agent: a.agent, source: a.source },
                        highlights: highlightsFor(f.file!),
                      })
                    }
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    {f.location} ↗
                  </button>
                </>
              ) : f.location ? (
                ` · ${f.location}`
              ) : (
                ""
              )}
              {f.owasp ? ` · ${f.owasp}` : ""}
            </p>
            {live && f.ruleId ? <MuteControl ruleId={f.ruleId} onChanged={onChanged} /> : null}
          </div>
        ))}
      </div>
    </Section>
  )
}

// MuteControl suppresses a finding rule with a required rationale (C4). Muting is
// recorded in the committed policy, so it stays auditable in the diff.
function MuteControl({ ruleId, onChanged }: { ruleId: string; onChanged?: () => void }) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = () => {
    if (reason.trim() === "") {
      setError("a rationale is required")
      return
    }
    setBusy(true)
    setError(null)
    muteFinding(ruleId, reason.trim())
      .then(() => {
        setOpen(false)
        onChanged?.()
      })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => setBusy(false))
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="mt-2 font-mono text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        Mute {ruleId}
      </button>
    )
  }
  return (
    <div className="mt-2 flex flex-col gap-1.5">
      <input
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder={`why is ${ruleId} an accepted false positive?`}
        className="w-full rounded-md border border-border bg-card px-2 py-1 font-mono text-[11px] text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
      />
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={submit}
          className="rounded-md border border-border px-2 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:bg-muted/40 disabled:opacity-50"
        >
          {busy ? "…" : "Confirm mute"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="font-mono text-[11px] text-muted-foreground hover:text-foreground"
        >
          cancel
        </button>
        {error ? <span className="font-mono text-[11px] text-sev-critical">{error}</span> : null}
      </div>
    </div>
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

function Activity({ name, live }: { name: string; live: boolean }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null)
  const [reload, setReload] = useState(0)
  useEffect(() => {
    let cancelled = false
    fetch(`/api/audit?server=${encodeURIComponent(name)}`)
      .then((r) => (r.ok ? r.json() : { events: [] }))
      .then((d: { events?: AuditEvent[] }) => !cancelled && setEvents(d.events ?? []))
      .catch(() => !cancelled && setEvents([]))
    return () => {
      cancelled = true
    }
  }, [name, reload])

  const egressHosts = Array.from(
    new Set((events ?? []).filter((e) => e.kind === "egress" && e.host).map((e) => e.host as string)),
  )

  return (
    <Section title="Runtime activity">
      {live && egressHosts.length > 0 ? (
        <EgressAllowlist server={name} hosts={egressHosts} onChanged={() => setReload((n) => n + 1)} />
      ) : null}
      {events === null ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : events.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No audit events. Wrap this server with <span className="font-mono">assay wrap</span> to record tool
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

// EgressAllowlist offers one-click "allow this host for this skill" (D2). Each
// click writes a per-server AllowHosts rule that the egress proxy enforces.
function EgressAllowlist({
  server,
  hosts,
  onChanged,
}: {
  server: string
  hosts: string[]
  onChanged?: () => void
}) {
  const [busy, setBusy] = useState<string | null>(null)
  const [done, setDone] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)

  const allow = (host: string) => {
    setBusy(host)
    setError(null)
    allowEgress(server, host)
      .then(() => {
        setDone((d) => new Set(d).add(host))
        onChanged?.()
      })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => setBusy(null))
  }

  return (
    <div className="mb-3 rounded-md border border-border bg-background p-2.5">
      <p className="mb-1.5 flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
        <Network className="h-3 w-3" /> Egress allowlist
      </p>
      <div className="flex flex-col gap-1">
        {hosts.map((h) => (
          <div key={h} className="flex items-baseline justify-between gap-3 font-mono text-[11px]">
            <span className="truncate text-foreground">{h}</span>
            {done.has(h) ? (
              <span className="shrink-0 text-ok">allowed</span>
            ) : (
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => allow(h)}
                className="shrink-0 rounded border border-border px-2 py-0.5 text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground disabled:opacity-50"
              >
                {busy === h ? "…" : "Allow"}
              </button>
            )}
          </div>
        ))}
      </div>
      {error ? <p className="mt-1.5 text-[11px] text-sev-critical">{error}</p> : null}
    </div>
  )
}
