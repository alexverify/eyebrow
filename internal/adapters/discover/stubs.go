package discover

import (
	"context"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// Codex is a documented seam. Its config is TOML (~/.codex/config.toml,
// [mcp_servers.<name>]); see codex.go once implemented. Kept as a no-op here
// until then so Default can reference it.
type Codex struct{}

// Tool returns the canonical tool id.
func (Codex) Tool() string { return "codex" }

// Discover satisfies ports.Discoverer (currently a no-op).
func (Codex) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	return nil, nil
}
