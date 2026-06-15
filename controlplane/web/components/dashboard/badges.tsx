import { cn } from "@/lib/utils"
import { SEVERITY_STYLES, DRIFT_STYLES, VERDICT_STYLES } from "@/lib/scan-utils"
import type { Severity, DriftStatus, Verdict, Finding } from "@/lib/scan-data"

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLES[severity]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide",
        s.bg,
        s.border,
        s.text,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} aria-hidden />
      {s.label}
    </span>
  )
}

export function DriftBadge({ status }: { status: DriftStatus }) {
  const d = DRIFT_STYLES[status]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium",
        d.bg,
        d.border,
        d.text,
      )}
    >
      {d.label}
    </span>
  )
}

// LivenessBadge marks how exercised the finding's artifact is (F3). Only the
// positive signals (live / exercised) are shown — "unknown" (no telemetry) is
// the silent baseline, so the badge highlights what is bad *and running*.
export function LivenessBadge({ liveness }: { liveness?: Finding["liveness"] }) {
  if (liveness !== "live" && liveness !== "exercised") return null
  const live = liveness === "live"
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide",
        live ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical" : "border-border bg-muted/40 text-muted-foreground",
      )}
      title={
        live
          ? "This artifact ran recently — its risky paths are live, not hypothetical."
          : "This artifact has run at least once."
      }
    >
      {live ? <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sev-critical" aria-hidden /> : null}
      {live ? "Live" : "Exercised"}
    </span>
  )
}

// ReachBadge marks a finding in a non-runtime path (H2). It renders only for
// inert findings — reachable is the silent default — so the badge calls out
// likely noise without cluttering real findings.
export function ReachBadge({ reach }: { reach?: Finding["reach"] }) {
  if (reach !== "inert") return null
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border border-border bg-muted/40 px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide text-muted-foreground"
      title="This finding sits in a test / example / vendored path that does not run in production — likely noise. Demoted, not hidden."
    >
      inert path
    </span>
  )
}

export function VerdictBadge({ verdict, score }: { verdict: Verdict; score?: number }) {
  const v = VERDICT_STYLES[verdict]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium",
        v.bg,
        v.border,
        v.text,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", v.dot)} aria-hidden />
      {v.label}
      {typeof score === "number" ? <span className="tabular-nums opacity-80">{score}</span> : null}
    </span>
  )
}
