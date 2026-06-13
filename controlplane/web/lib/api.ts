// Types mirror the Go domain JSON the dashboard backend serves under /api.
// They are intentionally partial — only the fields the UI renders.

export interface Finding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp?: string;
  file?: string;
  line?: number;
  explanation?: string;
}

export interface Source {
  kind: string;
  ref?: string;
  integrity?: string;
}

export interface Artifact {
  id: string;
  tool: string;
  scope: string;
  type: string;
  name: string;
  source: Source;
  findings?: Finding[];
  contentHash?: string;
}

export interface Lockfile {
  version: number;
  generatedAt: string;
  generator: string;
  artifacts: Artifact[];
}

export interface Change {
  kind: string;
  id: string;
  name: string;
  old?: string;
  new?: string;
}

export interface Diff {
  changes: Change[];
}

export interface AuditEvent {
  ts: string;
  session: string;
  server: string;
  kind: string;
  tool?: string;
  status?: string;
  host?: string;
  method?: string;
  detail?: string;
  redactions?: number;
}

export interface AuditSummary {
  total: number;
  sessions: number;
  toolCalls: number;
  denied: number;
  egress: number;
  redactions: number;
}

export interface AuditResponse {
  events: AuditEvent[];
  summary: AuditSummary;
}

// The dashboard is served by the same Go process as the API, so relative paths
// resolve to it whether opened at 127.0.0.1:7113 or proxied during `next dev`.
async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path} → ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  inventory: () => get<Lockfile>("/api/inventory"),
  drift: () => get<Diff>("/api/drift"),
  audit: () => get<AuditResponse>("/api/audit"),
};

export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function worstSeverity(findings?: Finding[]): string | null {
  if (!findings || findings.length === 0) return null;
  return findings.reduce(
    (w, f) => (SEVERITY_RANK[f.severity] > (SEVERITY_RANK[w] ?? -1) ? f.severity : w),
    "info",
  );
}
