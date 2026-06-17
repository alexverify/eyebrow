// Package client is the CLI-side HTTP client for the self-hostable team control
// plane (Component 3b). It is strictly opt-in: the CLI works fully offline
// without it, and a caller treats any client error as "fall back to local."
//
// Implemented:
//
//	POST /v1/snapshots     submit this machine's content-free fleet snapshot (4a)
//	GET  /v1/fleet         read the org's aggregated blast-radius report (4a)
//	GET  /v1/gate          run the fleet CI gate over submitted snapshots (4c)
//	POST /v1/audit         ingest this machine's audit events, batched (4d)
//	GET  /v1/alerts        read the org's derived team alerts (4d)
//	GET  /v1/policy        pull the org policy (4b; 404 → keep local policy)
//	GET  /v1/registry/keys pull the org's trusted signing keys (4b)
//	GET  /v1/healthz       liveness check
//
// Planned (later slices): POST /v1/artifacts/:id/approve,
// GET /v1/reputation/:hash. See docs/privacy.md for what each call sends.
package client
