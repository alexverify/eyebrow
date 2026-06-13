import {
  SEVERITY_ORDER,
  type Artifact,
  type Finding,
  type Severity,
  type DriftStatus,
} from "@/lib/scan-data"

export interface FlatFinding extends Finding {
  artifactId: string
  artifactName: string
  agent: Artifact["agent"]
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
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
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
