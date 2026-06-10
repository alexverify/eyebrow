// Package sandbox will generate and apply OS isolation profiles for sandboxed
// MCP servers (Component 2).
//
// Planned design: a Profile abstraction with platform backends —
//   - Linux: bubblewrap (bwrap) — mount/PID/user namespaces, an allowlisted
//     read-write workspace, the rest read-only or unmounted, egress forced
//     through the local proxy.
//   - macOS: Seatbelt via sandbox-exec with a generated .sb profile
//     ((deny default), allow workspace reads/writes, deny network except the
//     local proxy port).
//
// Sensitive paths (~/.ssh, ~/.aws, ~/.config/solana, keychain, browser dirs)
// are denied by default. Anthropic's open-source sandbox-runtime is the
// reference. Not yet implemented.
package sandbox
