"use client";

import { useEffect, useState } from "react";
import {
  api,
  worstSeverity,
  type Lockfile,
  type Diff,
  type AuditResponse,
} from "@/lib/api";

export default function Dashboard() {
  const [inv, setInv] = useState<Lockfile | null>(null);
  const [drift, setDrift] = useState<Diff | null>(null);
  const [audit, setAudit] = useState<AuditResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.inventory(), api.drift(), api.audit()])
      .then(([i, d, a]) => {
        setInv(i);
        setDrift(d);
        setAudit(a);
      })
      .catch((e) => setError(String(e)));
  }, []);

  if (error) {
    return (
      <main>
        <Header />
        <p className="error">Could not reach the agentguard backend: {error}</p>
      </main>
    );
  }

  const artifacts = inv?.artifacts ?? [];
  const changes = drift?.changes ?? [];
  const findingCount = artifacts.reduce((n, a) => n + (a.findings?.length ?? 0), 0);
  const criticalOrHigh = artifacts.filter((a) => {
    const w = worstSeverity(a.findings);
    return w === "critical" || w === "high";
  }).length;

  return (
    <main>
      <Header />
      <p className="meta">
        {inv ? `generated ${inv.generatedAt} · ${inv.generator}` : "loading…"}
      </p>

      <div className="cards">
        <Card label="artifacts" n={artifacts.length} />
        <Card label="drift" n={changes.length} alert={changes.length > 0} />
        <Card label="findings" n={findingCount} alert={criticalOrHigh > 0} />
        <Card label="tool calls" n={audit?.summary.toolCalls ?? 0} />
        <Card label="denied" n={audit?.summary.denied ?? 0} alert={(audit?.summary.denied ?? 0) > 0} />
      </div>

      <Inventory lf={inv} />
      <Drift diff={drift} />
      <Audit audit={audit} />
    </main>
  );
}

function Header() {
  return (
    <header className="top">
      <h1>agentguard</h1>
      <span className="tag">dashboard</span>
    </header>
  );
}

function Card({ label, n, alert }: { label: string; n: number; alert?: boolean }) {
  return (
    <div className={`card${alert ? " alert" : ""}`}>
      <div className="n">{n}</div>
      <div className="l">{label}</div>
    </div>
  );
}

function Inventory({ lf }: { lf: Lockfile | null }) {
  const artifacts = lf?.artifacts ?? [];
  return (
    <section>
      <h2>Inventory</h2>
      {artifacts.length === 0 ? (
        <p className="empty">No artifacts discovered.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>tool</th>
              <th>type</th>
              <th>name</th>
              <th>source</th>
              <th>findings</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map((a) => {
              const w = worstSeverity(a.findings);
              return (
                <tr key={a.id}>
                  <td>{a.tool}</td>
                  <td>{a.type}</td>
                  <td>{a.name}</td>
                  <td className="mono">{a.source?.kind}</td>
                  <td>
                    {a.findings?.length ? (
                      <span className={`sev sev-${w}`}>
                        {a.findings.length} · {w}
                      </span>
                    ) : (
                      <span className="clean">clean</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Drift({ diff }: { diff: Diff | null }) {
  const changes = diff?.changes ?? [];
  return (
    <section>
      <h2>Drift vs lockfile</h2>
      {changes.length === 0 ? (
        <p className="clean">No drift — current state matches the lockfile.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>kind</th>
              <th>artifact</th>
              <th>change</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((c, i) => (
              <tr key={`${c.id}-${c.kind}-${i}`}>
                <td>{c.kind}</td>
                <td>{c.name || c.id}</td>
                <td className="mono">
                  {c.old ? `${c.old} → ${c.new ?? ""}` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Audit({ audit }: { audit: AuditResponse | null }) {
  const events = (audit?.events ?? []).slice(-200).reverse();
  return (
    <section>
      <h2>Audit timeline</h2>
      {events.length === 0 ? (
        <p className="empty">No audit events. Run servers under `agentguard wrap`.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>time</th>
              <th>server</th>
              <th>kind</th>
              <th>tool / host</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={`${e.session}-${i}`}>
                <td className="mono">{e.ts?.replace("T", " ").replace("Z", "")}</td>
                <td>{e.server}</td>
                <td>{e.kind}</td>
                <td className="mono">{e.tool || e.host || ""}</td>
                <td>
                  {e.status ? (
                    <span className={`badge ${e.status === "denied" ? "denied" : e.status === "ok" ? "ok" : ""}`}>
                      {e.status}
                    </span>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
