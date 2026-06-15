import {
  SEVERITY_ORDER,
  type Artifact,
  type Finding,
  type Severity,
  type DriftStatus,
  type Verdict,
} from "@/lib/scan-data"

export interface FlatFinding extends Finding {
  artifactId: string
  artifactName: string
  agent: Artifact["agent"]
}

// LIVENESS_RANK orders findings of equal severity by exercised risk (F3): a
// finding on code that actually ran sorts above the same finding on code that
// only sits on disk.
const LIVENESS_RANK: Record<NonNullable<Finding["liveness"]>, number> = {
  live: 2,
  exercised: 1,
  unknown: 0,
}

function livenessWeight(f: Finding): number {
  return f.liveness ? LIVENESS_RANK[f.liveness] : 0
}

// reachWeight pushes inert findings (test/example/vendored paths — likely noise)
// below every reachable one, so the top of the list is all high-signal (H2).
function reachWeight(f: Finding): number {
  return f.reach === "inert" ? 1 : 0
}

export function getAllFindings(artifacts: Artifact[]): FlatFinding[] {
  return artifacts
    .flatMap((a) =>
      a.findings.map((f) => ({
        ...f,
        artifactId: a.id,
        artifactName: a.name,
        agent: a.agent,
      })),
    )
    .sort(
      (a, b) =>
        // Reachable first (noise sinks), then severity, then exercised risk so
        // live findings lead within a severity band.
        reachWeight(a) - reachWeight(b) ||
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        livenessWeight(b) - livenessWeight(a),
    )
}

export function severityCounts(artifacts: Artifact[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }
  for (const f of getAllFindings(artifacts)) counts[f.severity] += 1
  return counts
}

export function driftCounts(artifacts: Artifact[]): Record<DriftStatus, number> {
  const counts: Record<DriftStatus, number> = {
    verified: 0,
    updated: 0,
    drifted: 0,
    new: 0,
    unsigned: 0,
  }
  for (const a of artifacts) counts[a.drift] += 1
  return counts
}

export function topSeverity(a: Artifact): Severity | null {
  if (a.findings.length === 0) return null
  return [...a.findings].sort(
    (x, y) => SEVERITY_ORDER[x.severity] - SEVERITY_ORDER[y.severity],
  )[0].severity
}

export const SEVERITY_STYLES: Record<
  Severity,
  { label: string; dot: string; text: string; bg: string; border: string }
> = {
  critical: {
    label: "Critical",
    dot: "bg-sev-critical",
    text: "text-sev-critical",
    bg: "bg-sev-critical/10",
    border: "border-sev-critical/30",
  },
  high: {
    label: "High",
    dot: "bg-sev-high",
    text: "text-sev-high",
    bg: "bg-sev-high/10",
    border: "border-sev-high/30",
  },
  medium: {
    label: "Medium",
    dot: "bg-sev-medium",
    text: "text-sev-medium",
    bg: "bg-sev-medium/10",
    border: "border-sev-medium/30",
  },
  low: {
    label: "Low",
    dot: "bg-sev-low",
    text: "text-sev-low",
    bg: "bg-sev-low/10",
    border: "border-sev-low/30",
  },
}

export const DRIFT_STYLES: Record<
  DriftStatus,
  { label: string; text: string; bg: string; border: string }
> = {
  verified: {
    label: "Verified",
    text: "text-ok",
    bg: "bg-ok/10",
    border: "border-ok/30",
  },
  updated: {
    label: "Updated",
    text: "text-sev-medium",
    bg: "bg-sev-medium/10",
    border: "border-sev-medium/30",
  },
  drifted: {
    label: "Drifted",
    text: "text-sev-critical",
    bg: "bg-sev-critical/10",
    border: "border-sev-critical/30",
  },
  new: {
    label: "Unaudited",
    text: "text-sev-medium",
    bg: "bg-sev-medium/10",
    border: "border-sev-medium/30",
  },
  unsigned: {
    label: "Unsigned",
    text: "text-sev-high",
    bg: "bg-sev-high/10",
    border: "border-sev-high/30",
  },
}

export const VERDICT_STYLES: Record<
  Verdict,
  { label: string; text: string; bg: string; border: string; dot: string }
> = {
  trusted: {
    label: "Trusted",
    text: "text-ok",
    bg: "bg-ok/10",
    border: "border-ok/30",
    dot: "bg-ok",
  },
  review: {
    label: "Review",
    text: "text-sev-high",
    bg: "bg-sev-high/10",
    border: "border-sev-high/30",
    dot: "bg-sev-high",
  },
  quarantine: {
    label: "Quarantine",
    text: "text-sev-critical",
    bg: "bg-sev-critical/10",
    border: "border-sev-critical/30",
    dot: "bg-sev-critical",
  },
}

export function verdictCounts(artifacts: Artifact[]): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { trusted: 0, review: 0, quarantine: 0 }
  for (const a of artifacts) {
    const v = a.verdict ?? "review"
    counts[v] += 1
  }
  return counts
}
