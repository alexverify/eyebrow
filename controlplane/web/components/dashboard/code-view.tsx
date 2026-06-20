"use client"

import { useEffect, useRef, useState } from "react"
import { X } from "lucide-react"

// CodeTarget identifies the file to open and where to anchor it. highlights are
// the finding lines to mark (used by the highlighting slice); focusLine is the
// line scrolled into view on open.
export interface CodeTarget {
  artifactId: string
  file: string
  focusLine?: number
  highlights?: { line: number; title: string; severity: string }[]
}

// CodeView is a modal overlay that shows one artifact file with line numbers,
// fetched live from the loopback backend (GET /api/source). It scrolls the
// flagged line into view and closes on Esc or a backdrop click. Rendering the
// finding highlights themselves is layered on in a later slice.
export function CodeView({ target, onClose }: { target: CodeTarget | null; onClose: () => void }) {
  const [content, setContent] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const focusRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!target) return
    setContent(null)
    setError(null)
    const url = `/api/source?id=${encodeURIComponent(target.artifactId)}&file=${encodeURIComponent(target.file)}`
    fetch(url)
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.text()).trim() || `HTTP ${r.status}`)
        return (await r.json()) as { content: string }
      })
      .then((d) => setContent(d.content))
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load file"))
  }, [target])

  useEffect(() => {
    if (!target) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [target, onClose])

  // Once the file renders, bring the flagged line to the middle of the viewport.
  useEffect(() => {
    if (content !== null) focusRef.current?.scrollIntoView({ block: "center" })
  }, [content])

  if (!target) return null
  const lines = content === null ? [] : content.split("\n")

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-lg border border-border bg-card shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <span className="font-mono text-sm text-foreground">
            {target.file}
            {target.focusLine ? <span className="text-muted-foreground">:{target.focusLine}</span> : null}
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="overflow-auto">
          {error ? (
            <p className="p-4 font-mono text-xs text-sev-high">{error}</p>
          ) : content === null ? (
            <p className="p-4 font-mono text-xs text-muted-foreground">loading…</p>
          ) : (
            <pre className="py-2 font-mono text-xs leading-relaxed">
              {lines.map((ln, i) => {
                const n = i + 1
                const isFocus = n === target.focusLine
                return (
                  <div key={n} ref={isFocus ? focusRef : undefined} className="flex px-2">
                    <span className="w-12 shrink-0 select-none pr-3 text-right text-muted-foreground/60">
                      {n}
                    </span>
                    <code className="whitespace-pre-wrap break-words text-foreground">{ln || " "}</code>
                  </div>
                )
              })}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}
