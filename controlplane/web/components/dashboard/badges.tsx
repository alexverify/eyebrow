"use client"

import { cn } from "@/lib/utils"
import { SEVERITY_STYLES, DRIFT_STYLES, VERDICT_STYLES } from "@/lib/scan-utils"
import type { Severity, DriftStatus, Verdict, Finding, Artifact } from "@/lib/scan-data"
import { useTeamMode } from "@/components/dashboard/team-mode"

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

// SafeBadge marks a finding flagged as an accepted false positive: still shown,
// but acknowledged. A stale flag (code changed since it was flagged) is tinted
// to invite a re-check.
export function SafeBadge({ stale }: { stale?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium",
        stale ? "border-sev-medium/40 bg-sev-medium/10 text-sev-medium" : "border-ok/30 bg-ok/10 text-ok",
      )}
      title={stale ? "Flagged safe, but the code changed since — worth re-checking." : "Flagged as an accepted false positive."}
    >
      ✓ safe{stale ? " (stale)" : ""}
    </span>
  )
}

export function DriftBadge({ status, approved }: { status: DriftStatus; approved?: boolean }) {
  const teamMode = useTeamMode()
  const d = DRIFT_STYLES[status]

  // Solo mode hides the signing vocabulary: an approved artifact is just
  // "Approved", an unapproved-but-locked one is "Not approved".
  if (!teamMode) {
    if (status === "verified") {
      return <Pill style={DRIFT_STYLES.verified} label="Approved" />
    }
    if (status === "unsigned") {
      return <Pill style={DRIFT_STYLES.updated} label="Not approved" />
    }
    return <Pill style={d} label={d.label} />
  }

  // Team mode keeps the full vocabulary. An approved-but-unsigned artifact is a
  // softer state than a never-approved one: the approve succeeded, only the
  // signature is missing — relabel and drop the urgent palette to "updated".
  const approvedUnsigned = status === "unsigned" && approved
  return (
    <Pill
      style={approvedUnsigned ? DRIFT_STYLES.updated : d}
      label={approvedUnsigned ? "Approved · unsigned" : d.label}
      title={approvedUnsigned ? "Approved from the dashboard but not yet signed by a trusted key." : undefined}
    />
  )
}

function Pill({
  style,
  label,
  title,
}: {
  style: { bg: string; border: string; text: string }
  label: string
  title?: string
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium",
        style.bg,
        style.border,
        style.text,
      )}
      title={title}
    >
      {label}
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

// ReputationBadge shows the opt-in community trust signal (H3): how many other
// users vouch for this exact content hash. Renders only when the hash is known
// to the corpus — an unknown hash is silent (never a negative claim).
export function ReputationBadge({ reputation }: { reputation?: Artifact["reputation"] }) {
  if (!reputation || reputation.grade === "unknown" || reputation.trusters <= 0) return null
  const established = reputation.grade === "established"
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium",
        established ? "border-ok/40 bg-ok/10 text-ok" : "border-border bg-muted/40 text-muted-foreground",
      )}
      title={`Trusted by ${reputation.trusters} other eyebrow users${reputation.firstSeen ? `, first seen ${reputation.firstSeen}` : ""}. Hash-only, opt-in signal.`}
    >
      ✓ {reputation.trusters} trust
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
