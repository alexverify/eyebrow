"use client"

import { useEffect, useRef, useState } from "react"
import { CopyCommand } from "@/components/copy-command"
import { GithubIcon } from "@/components/github-icon"

type Line = {
  text: string
  tone?: "default" | "muted" | "warn"
}

const AUDIT_LINES: Line[] = [
  { text: "$ npx eyebrow audit", tone: "muted" },
  { text: "scanning 14 installed extensions across 4 agents...", tone: "muted" },
  { text: "" },
  { text: "ok   git-flow-helper@2.1.0          sha256:9f3a…c012", tone: "default" },
  { text: "ok   postgres-mcp-server@0.4.2      sha256:1b77…ae90", tone: "default" },
  { text: "ok   notion-sync-skill@1.0.5        sha256:6d4e…ff21", tone: "default" },
  { text: "warn web-fetch-pro@3.2.1            sha256:c80a…1d44", tone: "default" },
  { text: "  ⚠ remote code execution pattern: curl | sh detected", tone: "warn" },
  { text: "warn repo-indexer-mcp@0.9.0         sha256:4ec1…77bc", tone: "default" },
  { text: "  ⚠ hash drift — contents changed since last audit", tone: "warn" },
  { text: "" },
  { text: "12 ok · 2 flagged · review before your agent runs them", tone: "muted" },
]

function useReducedMotion() {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)")
    setReduced(mq.matches)
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches)
    mq.addEventListener("change", handler)
    return () => mq.removeEventListener("change", handler)
  }, [])
  return reduced
}

function AuditTerminal() {
  const reduced = useReducedMotion()
  const [visibleCount, setVisibleCount] = useState(0)
  const started = useRef(false)

  useEffect(() => {
    if (reduced) {
      setVisibleCount(AUDIT_LINES.length)
      return
    }
    if (started.current) return
    started.current = true
    let i = 0
    const interval = setInterval(() => {
      i += 1
      setVisibleCount(i)
      if (i >= AUDIT_LINES.length) clearInterval(interval)
    }, 280)
    return () => clearInterval(interval)
  }, [reduced])

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-card shadow-sm">
      <div className="flex items-center gap-2 border-b border-border bg-secondary px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40" aria-hidden="true" />
        <span className="ml-2 font-mono text-xs text-muted-foreground">eyebrow — audit</span>
      </div>
      <pre className="overflow-x-auto px-4 py-4 font-mono text-[13px] leading-6">
        <code>
          {AUDIT_LINES.slice(0, visibleCount).map((line, idx) => (
            <div
              key={idx}
              className={
                line.tone === "warn"
                  ? "text-primary"
                  : line.tone === "muted"
                    ? "text-muted-foreground"
                    : "text-card-foreground"
              }
            >
              {line.text || "\u00A0"}
            </div>
          ))}
        </code>
      </pre>
    </div>
  )
}

export function Hero() {
  return (
    <section className="border-b border-border">
      <div className="mx-auto max-w-[1100px] px-6 py-20 md:py-28">
        <div className="grid items-center gap-12 lg:grid-cols-2">
          <div>
            <h1 className="text-balance font-mono text-3xl font-semibold leading-tight tracking-tight md:text-4xl lg:text-[2.75rem]">
              The skill you installed yesterday may be reading your seed phrase right now.
            </h1>
            <p className="mt-6 max-w-xl text-pretty leading-relaxed text-muted-foreground">
              Eyebrow is npm audit + lockfile + permission firewall for the skills, MCP servers, and plugins you
              install into Claude Code, Cursor, Codex, and other AI coding agents. Open source. No account. Audit in
              seconds.
            </p>
            <div className="mt-8 flex flex-col items-start gap-4">
              <CopyCommand />
              <a
                href="https://github.com/alexverify/eyebrow"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-md border border-border bg-transparent px-4 py-2.5 font-mono text-sm text-foreground transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              >
                <GithubIcon className="h-4 w-4" />
                View on GitHub
              </a>
            </div>
          </div>
          <AuditTerminal />
        </div>
      </div>
    </section>
  )
}
