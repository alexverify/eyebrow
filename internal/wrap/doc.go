// Package wrap will implement Component 2's MCP interposition supervisor.
//
// Planned design: `agentguard wrap` rewrites (or overlays) a tool's MCP config
// so each server points at the supervisor instead of the real command. The
// supervisor spawns the real server inside a sandbox (see internal/sandbox),
// relays JSON-RPC over stdio in both directions, inspects each tools/call
// request and result, enforces policy (tool allowlist, argument constraints),
// and emits an audit event per call (see internal/audit). Remote HTTP/SSE
// servers are fronted by an HTTP proxy applying the same inspection.
//
// This package is a documented seam: it plugs into the existing artifact and
// lockfile model and is driven by a future `wrap` CLI command. Not yet
// implemented.
package wrap
