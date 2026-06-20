"use client"

import { useState } from "react"
import { Check, Copy } from "lucide-react"

export function CopyCommand({ command = "npx eyebrow audit" }: { command?: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard unavailable; fail quietly.
    }
  }

  return (
    <div className="flex w-full max-w-md items-center justify-between gap-3 rounded-md border border-border bg-card px-4 py-3 font-mono text-sm">
      <span className="flex items-center gap-2 truncate">
        <span aria-hidden="true" className="text-muted-foreground">
          $
        </span>
        <span className="truncate text-card-foreground">{command}</span>
      </span>
      <button
        type="button"
        onClick={handleCopy}
        aria-label={copied ? "Copied to clipboard" : `Copy command: ${command}`}
        className="inline-flex shrink-0 items-center gap-1.5 rounded border border-border bg-secondary px-2.5 py-1 text-xs text-secondary-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      >
        {copied ? (
          <>
            <Check className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
            Copied
          </>
        ) : (
          <>
            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
            Copy
          </>
        )}
      </button>
    </div>
  )
}
