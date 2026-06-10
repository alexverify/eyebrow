// Package buildinfo exposes build-time metadata stamped via -ldflags.
// Kept dependency-free so every other package can import it cheaply.
package buildinfo

// Version is the release version, injected at build time
// (see the Makefile's LDFLAGS). It defaults to "dev" for local builds.
var Version = "dev"

// Name is the canonical tool name, used in generated artifacts (e.g. the
// lockfile "generator" field) and user-facing output.
const Name = "agentguard"

// UserAgent returns the value used to identify the tool to external
// services (e.g. the future control-plane client and egress proxy).
func UserAgent() string {
	return Name + "/" + Version
}
