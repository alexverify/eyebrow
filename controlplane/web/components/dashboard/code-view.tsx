"use client"

import { type ReactNode, useEffect, useMemo, useRef, useState } from "react"
import { ArrowLeft, ChevronUp, ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"

// CodeTarget identifies the file to open and where to anchor it. highlights are
// the finding lines to mark; focusLine is the line scrolled into view on open.
// snippet lets the view degrade to the stored evidence when the file can't be
// read (e.g. a remote artifact whose bytes weren't captured).
export interface CodeHighlight {
  line: number
  title: string
  severity: string
  snippet?: string
  ruleId?: string
  owasp?: string
  detail?: string
}

export interface CodeTarget {
  artifactId: string
  file: string
  focusLine?: number
  artifact?: { name: string; kind: string; agent: string; source?: string }
  highlights?: CodeHighlight[]
}

// CodeView is a full-screen view that shows one artifact file with line numbers,
// fetched live from the loopback backend (GET /api/source). It marks the flagged
// lines, scrolls the active one into view, lets you step between findings in the
// same file, and falls back to the stored snippets when the file is unreadable.
// Opening pushes a history entry so the browser Back button (and Esc, and the
// ← Back control) return to the dashboard.
export function CodeView({ target, onClose }: { target: CodeTarget | null; onClose: () => void }) {
  const [content, setContent] = useState<string | null>(null)
  const [absPath, setAbsPath] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeLine, setActiveLine] = useState<number | undefined>(undefined)
  const focusRef = useRef<HTMLDivElement | null>(null)

  // The flagged lines, de-duplicated and ordered, drive prev/next navigation.
  const navLines = useMemo(() => {
    const set = new Set<number>()
    for (const h of target?.highlights ?? []) if (h.line > 0) set.add(h.line)
    return [...set].sort((a, b) => a - b)
  }, [target])

  useEffect(() => {
    if (!target) return
    setContent(null)
    setAbsPath(null)
    setError(null)
    setActiveLine(target.focusLine)
    const url = `/api/source?id=${encodeURIComponent(target.artifactId)}&file=${encodeURIComponent(target.file)}`
    fetch(url)
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.text()).trim() || `HTTP ${r.status}`)
        return (await r.json()) as { content: string; absPath?: string }
      })
      .then((d) => {
        setContent(d.content)
        setAbsPath(d.absPath ?? null)
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load file"))
  }, [target])

  // Push a history entry on open so the browser Back button returns to the
  // dashboard; popping it (Back, Esc, or the ← Back control via history.back)
  // drives onClose, keeping history clean.
  useEffect(() => {
    if (!target) return
    window.history.pushState({ assaySource: true }, "")
    const onPop = () => onClose()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") window.history.back()
    }
    window.addEventListener("popstate", onPop)
    window.addEventListener("keydown", onKey)
    return () => {
      window.removeEventListener("popstate", onPop)
      window.removeEventListener("keydown", onKey)
    }
  }, [target, onClose])

  // Bring the active flagged line to the middle of the viewport on open and on
  // every prev/next step.
  useEffect(() => {
    if (content !== null) focusRef.current?.scrollIntoView({ block: "center" })
  }, [content, activeLine])

  if (!target) return null

  const lines = content === null ? [] : content.split("\n")
  const marks = new Map<number, { title: string; severity: string }>()
  for (const h of target.highlights ?? []) {
    if (h.line > 0) marks.set(h.line, { title: h.title, severity: h.severity })
  }

  const activeFinding =
    (target.highlights ?? []).find((h) => h.line === activeLine) ?? target.highlights?.[0]
  const idx = activeLine ? navLines.indexOf(activeLine) : -1
  const step = (delta: number) => {
    if (navLines.length === 0) return
    const next = idx < 0 ? 0 : (idx + delta + navLines.length) % navLines.length
    setActiveLine(navLines[next])
  }

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-background">
      <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={() => window.history.back()}
            className="flex shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </button>
          <span className="min-w-0 truncate font-mono text-sm text-foreground">
            {target.file}
            {activeLine ? <span className="text-muted-foreground">:{activeLine}</span> : null}
          </span>
        </div>
        {navLines.length > 1 ? (
          <div className="flex shrink-0 items-center gap-2">
            <span className="font-mono text-[11px] text-muted-foreground">
              finding {Math.max(idx, 0) + 1}/{navLines.length}
            </span>
            <button
              type="button"
              onClick={() => step(-1)}
              aria-label="Previous finding"
              className="text-muted-foreground hover:text-foreground"
            >
              <ChevronUp className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={() => step(1)}
              aria-label="Next finding"
              className="text-muted-foreground hover:text-foreground"
            >
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        ) : null}
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 overflow-auto">
        {content === null && error === null ? (
            <p className="p-4 font-mono text-xs text-muted-foreground">loading…</p>
          ) : error !== null ? (
            <SnippetFallback target={target} error={error} />
          ) : (
            <pre className="py-2 font-mono text-xs leading-relaxed">
              {lines.map((ln, i) => {
                const n = i + 1
                const isFocus = n === activeLine
                const mark = marks.get(n)
                return (
                  <div
                    key={n}
                    ref={isFocus ? focusRef : undefined}
                    className={cn(
                      "flex px-2",
                      mark && "border-l-2 border-sev-high bg-sev-high/10",
                      isFocus && mark && "bg-sev-high/20",
                    )}
                  >
                    <span
                      className={cn(
                        "w-12 shrink-0 select-none pr-3 text-right",
                        mark ? "text-sev-high" : "text-muted-foreground/60",
                      )}
                    >
                      {n}
                    </span>
                    <code className="whitespace-pre-wrap break-words text-foreground">{ln || " "}</code>
                    {mark ? (
                      <span className="ml-3 shrink-0 self-center rounded border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 text-[10px] font-medium text-sev-high">
                        ◀ {mark.title}
                      </span>
                    ) : null}
                  </div>
                )
              })}
            </pre>
          )}
        </div>
        <DetailPanel target={target} absPath={absPath} active={activeFinding} />
      </div>
    </div>
  )
}

// DetailPanel is the right-hand context column: where the file lives on disk,
// the artifact it belongs to, and the focused finding's rule detail.
function DetailPanel({
  target,
  absPath,
  active,
}: {
  target: CodeTarget
  absPath: string | null
  active?: CodeHighlight
}) {
  return (
    <aside className="hidden w-80 shrink-0 space-y-5 overflow-auto border-l border-border p-5 md:block">
      <Field label="File">
        <p className="break-all font-mono text-xs text-foreground">{absPath ?? target.file}</p>
      </Field>
      {target.artifact ? (
        <Field label="Artifact">
          <p className="font-mono text-xs text-foreground">{target.artifact.name}</p>
          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
            {target.artifact.kind} · {target.artifact.agent}
          </p>
          {target.artifact.source ? (
            <p className="mt-0.5 break-all font-mono text-[11px] text-muted-foreground">
              {target.artifact.source}
            </p>
          ) : null}
        </Field>
      ) : null}
      {active ? (
        <Field label="Finding">
          <div className="flex items-center gap-2">
            <span className="rounded border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-sev-high">
              {active.severity}
            </span>
            {active.ruleId ? (
              <span className="font-mono text-[11px] text-muted-foreground">{active.ruleId}</span>
            ) : null}
          </div>
          <p className="mt-1.5 text-xs text-foreground">{active.title}</p>
          {active.owasp ? (
            <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">OWASP {active.owasp}</p>
          ) : null}
          {active.detail ? (
            <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{active.detail}</p>
          ) : null}
        </Field>
      ) : null}
    </aside>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      {children}
    </div>
  )
}

// SnippetFallback renders the stored evidence for each finding when the file
// itself can't be read, so the view still shows the flagged code in context of
// its line and rule rather than just an error.
function SnippetFallback({ target, error }: { target: CodeTarget; error: string }) {
  const withSnippet = (target.highlights ?? []).filter((h) => h.snippet)
  return (
    <div className="space-y-3 p-4">
      <p className="font-mono text-[11px] text-muted-foreground">
        Couldn&apos;t load the file ({error}). Showing the stored evidence instead.
      </p>
      {withSnippet.length === 0 ? (
        <p className="font-mono text-xs text-muted-foreground">No snippet captured for this finding.</p>
      ) : (
        withSnippet.map((h, i) => (
          <div key={i} className="rounded-md border border-sev-high/40 bg-sev-high/10 p-3">
            <p className="font-mono text-[11px] text-sev-high">
              {target.file}:{h.line} · {h.title}
            </p>
            <code className="mt-2 block overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs text-foreground">
              {h.snippet}
            </code>
          </div>
        ))
      )}
    </div>
  )
}
