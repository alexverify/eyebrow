// Package client is the CLI-side HTTP client for the self-hostable team control
// plane (Component 3b). It is strictly opt-in: the CLI works fully offline
// without it, and a caller treats any client error as "fall back to local."
//
// Implemented (slice 4a):
//
//	POST /v1/snapshots   submit this machine's content-free fleet snapshot
//	GET  /v1/fleet       read the org's aggregated blast-radius report
//	GET  /v1/healthz     liveness check
//
// Planned (later slices): GET /v1/policy, GET /v1/registry/keys, POST /v1/audit,
// POST /v1/artifacts/:id/approve, GET /v1/alerts, GET /v1/reputation/:hash.
package client
