"use client"

import { useEffect, useState } from "react"
import { artifacts as mockArtifacts, type Artifact } from "@/lib/scan-data"

export interface ScanState {
  artifacts: Artifact[]
  loading: boolean
  live: boolean // true once data came from the Go /api/scan endpoint
  error: string | null
}

/**
 * useScan fetches the live inventory from the agentguard backend (/api/scan,
 * served by `agentguard dashboard`). When that endpoint is unreachable — e.g.
 * during `next dev` with no backend running — it falls back to the bundled
 * mock data so the UI is still demoable.
 */
export function useScan(): ScanState {
  const [state, setState] = useState<ScanState>({
    artifacts: [],
    loading: true,
    live: false,
    error: null,
  })

  useEffect(() => {
    let cancelled = false
    fetch("/api/scan", { headers: { Accept: "application/json" } })
      .then((r) => {
        if (!r.ok) throw new Error(`/api/scan → ${r.status}`)
        return r.json()
      })
      .then((data: { artifacts?: Artifact[] }) => {
        if (cancelled) return
        setState({
          artifacts: data.artifacts ?? [],
          loading: false,
          live: true,
          error: null,
        })
      })
      .catch((err) => {
        if (cancelled) return
        // Backend not present (dev/demo): use mock data, surface why.
        setState({
          artifacts: mockArtifacts,
          loading: false,
          live: false,
          error: String(err),
        })
      })
    return () => {
      cancelled = true
    }
  }, [])

  return state
}
