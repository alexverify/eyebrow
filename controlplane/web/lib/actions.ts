"use client"

// Client helpers for the dashboard's write actions (approve / quarantine /
// freeze, plus the policy editor, finding mute, and egress allowlist). Each POST
// carries the X-Assay-Token header; the token is fetched once from the
// same-origin /api/token endpoint, which a cross-origin page cannot read. In
// demo mode (no backend) the fetch fails and the write affordances are hidden.

let tokenCache: string | null = null
let writableCache = false
let policyWritableCache = false
let teamModeCache = false

async function getToken(): Promise<string> {
  if (tokenCache !== null) return tokenCache
  const r = await fetch("/api/token")
  if (!r.ok) throw new Error("write token unavailable")
  const d = (await r.json()) as {
    token: string
    writable: boolean
    policyWritable?: boolean
    teamMode?: boolean
  }
  tokenCache = d.token
  writableCache = d.writable
  policyWritableCache = d.policyWritable ?? false
  teamModeCache = d.teamMode ?? false
  return tokenCache
}

/** isTeamMode reports whether a trusted-keys registry exists (team trust on). */
export async function isTeamMode(): Promise<boolean> {
  try {
    await getToken()
    return teamModeCache
  } catch {
    return false
  }
}

/** isWritable reports whether the backend exposes the lockfile write endpoints. */
export async function isWritable(): Promise<boolean> {
  try {
    await getToken()
    return writableCache
  } catch {
    return false
  }
}

/** isPolicyWritable reports whether the backend can edit the policy file. */
export async function isPolicyWritable(): Promise<boolean> {
  try {
    await getToken()
    return policyWritableCache
  } catch {
    return false
  }
}

async function postJSON(path: string, body: unknown): Promise<void> {
  const token = await getToken()
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Assay-Token": token },
    body: JSON.stringify(body),
  })
  if (!r.ok) {
    throw new Error(`${path} failed: ${(await r.text()).trim() || r.status}`)
  }
}

export type ActionKind = "approve" | "quarantine" | "freeze"

/** runAction POSTs a lockfile write to the backend; throws on any non-2xx. */
export function runAction(kind: ActionKind, id: string, on: boolean): Promise<void> {
  return postJSON(`/api/${kind}`, { id, on })
}

/**
 * accountAll approves every unaccounted (shadow) artifact at once: the backend
 * adds each to the lockfile and marks it approved, returning how many it
 * accounted for. Backs the "Approve all" action on the unaccounted banner.
 */
export async function accountAll(): Promise<{ count: number }> {
  const token = await getToken()
  const r = await fetch("/api/account-all", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Assay-Token": token },
  })
  if (!r.ok) {
    throw new Error(`/api/account-all failed: ${(await r.text()).trim() || r.status}`)
  }
  return (await r.json()) as { count: number }
}

/**
 * flagSafe marks (or clears) one finding as an accepted false positive. The
 * finding stays visible but the CI gate accepts it; persisted on the lockfile
 * entry. key is the finding's stable identity (rule|file|line).
 */
export function flagSafe(id: string, key: string, on: boolean): Promise<void> {
  return postJSON("/api/finding-safe", { id, key, on })
}

export interface PolicyLists {
  allowPublishers: string[]
  blockPublishers: string[]
  blockArtifacts: string[]
}

export interface PolicyMute {
  rule: string
  reason?: string
  by?: string
}

/** fetchPolicy reads the committed policy's editable lists and mutes. */
export async function fetchPolicy(): Promise<PolicyLists & { mutes: PolicyMute[] }> {
  const r = await fetch("/api/policy")
  if (!r.ok) throw new Error("policy unavailable")
  const d = (await r.json()) as Partial<PolicyLists> & { mutes?: PolicyMute[] }
  return {
    allowPublishers: d.allowPublishers ?? [],
    blockPublishers: d.blockPublishers ?? [],
    blockArtifacts: d.blockArtifacts ?? [],
    mutes: d.mutes ?? [],
  }
}

/** savePolicy replaces the policy's allow/block lists (C3). */
export function savePolicy(lists: PolicyLists): Promise<void> {
  return postJSON("/api/policy", lists)
}

/** muteFinding suppresses a rule with a recorded rationale (C4). */
export function muteFinding(rule: string, reason: string): Promise<void> {
  return postJSON("/api/mute", { rule, reason })
}

/** allowEgress adds a host to a server's egress allowlist (D2). */
export function allowEgress(server: string, host: string): Promise<void> {
  return postJSON("/api/egress-allow", { server, host })
}
