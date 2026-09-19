// Package engine is the public entry point to the eyebrow engine for Go
// programs that embed it: discover every AI tool artifact under a directory,
// pin and hash each one, run the static rules, and compare the result with an
// approved lockfile.
//
// The package wraps the same use cases the eyebrow CLI runs and returns the
// same lockfile bytes, so a lockfile produced here verifies with the CLI and
// the other way round.
//
// Stability: the API is versioned with the module. Until the module reaches
// v1, a breaking change to this package bumps the minor version.
//
// Concurrency: an *Engine is safe for concurrent use. Scan and Verify hold no
// mutable state between calls, so one Engine built with New may serve many
// concurrent requests.
//
// Resolution: unless Options.Offline is set, resolving a discovered artifact's
// source may run the git and npm binaries and make network requests to hosts
// named by the scanned content itself (a package registry, a git remote, an
// MCP server's declared URL). A hosted caller embedding this package should
// run it inside a sandboxed process — the same way the eyebrow CLI's own
// runtime firewall (`eyebrow wrap`) confines an MCP server — or set Offline to
// remove the network and subprocess surface entirely.
package engine
