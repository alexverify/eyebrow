// Package client will implement the control-plane HTTP client (Component 3).
//
// Planned design: a thin, retrying client over the control-plane API —
//
//	POST /v1/lockfiles            submit a machine/project snapshot
//	GET  /v1/policy               fetch org policy (the CLI pulls this)
//	POST /v1/audit                ingest runtime events (batched)
//	GET  /v1/registry/keys        trusted signing keys
//	POST /v1/artifacts/:id/approve team approval workflow
//	GET  /v1/alerts               drift / new-critical alerts
//
// It is optional and opt-in; the CLI works fully offline without it. Not yet
// implemented.
package client
