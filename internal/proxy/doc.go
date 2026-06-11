// Package proxy will implement Component 2's egress proxy with secret
// redaction.
//
// Planned design: a local forward proxy on 127.0.0.1 that sandboxed MCP servers
// must route through. It enforces a default-deny domain allowlist (per-server
// from the lockfile capabilities.network), redacts known secret shapes in
// request bodies/headers (AWS AKIA…, OpenAI/Anthropic keys, Solana/base58 seeds,
// JWTs, KEY=value env leaks) before forwarding, and logs every connection
// { server, host, method, bytesUp, bytesDown, allowed, redactions, ts } to the
// audit trail (see internal/domain/audit and internal/adapters/auditlog).
//
// Defaults for the MVP: fail-open-with-alert, because a security tool that
// silently breaks workflows gets uninstalled. Not yet implemented.
package proxy
