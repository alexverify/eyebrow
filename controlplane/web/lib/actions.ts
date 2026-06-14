"use client"

// Client helpers for the dashboard's write actions (approve / quarantine /
// freeze). Each POST carries the X-Agentguard-Token header; the token is fetched
// once from the same-origin /api/token endpoint, which a cross-origin page
// cannot read. In demo mode (no backend) the fetch fails and actions are hidden.

let tokenCache: string | null = null
let writableCache = false

async function getToken(): Promise<string> {
  if (tokenCache !== null) return tokenCache
  const r = await fetch("/api/token")
  if (!r.ok) throw new Error("write token unavailable")
  const d = (await r.json()) as { token: string; writable: boolean }
  tokenCache = d.token
  writableCache = d.writable
  return tokenCache
}

/** isWritable reports whether the backend exposes the write endpoints. */
export async function isWritable(): Promise<boolean> {
  try {
    await getToken()
    return writableCache
  } catch {
    return false
  }
}

export type ActionKind = "approve" | "quarantine" | "freeze"

/** runAction POSTs a write to the backend; throws on any non-2xx response. */
export async function runAction(kind: ActionKind, id: string, on: boolean): Promise<void> {
  const token = await getToken()
  const r = await fetch(`/api/${kind}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Agentguard-Token": token },
    body: JSON.stringify({ id, on }),
  })
  if (!r.ok) {
    throw new Error(`${kind} failed: ${(await r.text()).trim() || r.status}`)
  }
}
