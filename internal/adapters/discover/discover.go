// Package discover walks tool configurations and normalizes every skill, MCP
// server, plugin, hook, rule, and context file into the domain Artifact model.
//
// Each supported tool has its own discoverer; Multi aggregates them. Adding a
// tool is a one-line change to Default — the seam that keeps discovery
// resilient as tools and their config layouts drift between versions.
package discover

import (
	"context"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// ToolDiscoverer discovers artifacts for a single tool.
type ToolDiscoverer interface {
	ports.Discoverer
	// Tool returns the canonical tool identifier (e.g. "claude-code").
	Tool() string
}

// Multi aggregates several discoverers into one. A failure from any discoverer
// aborts the aggregate so a partial inventory is never mistaken for complete.
type Multi struct {
	tools []ports.Discoverer
}

// NewMulti composes discoverers.
func NewMulti(tools ...ports.Discoverer) *Multi { return &Multi{tools: tools} }

// Discover satisfies ports.Discoverer.
func (m *Multi) Discover(ctx context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, t := range m.tools {
		arts, err := t.Discover(ctx, scopes)
		if err != nil {
			return out, err
		}
		out = append(out, arts...)
	}
	return out, nil
}

// Default returns discoverers for every supported tool. Claude Code is fully
// implemented; the others are documented stubs (see stubs.go).
func Default() *Multi {
	return NewMulti(
		NewClaudeCode(),
		NewCursor(),
		Codex{},
		Gemini{},
		OpenCode{},
	)
}
