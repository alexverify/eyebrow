package discover

import (
	"context"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// The discoverers below are documented seams. Each returns an empty inventory
// today and is the place to implement that tool's config discovery, following
// the ClaudeCode/Cursor pattern. They are wired into Default so the inventory
// grows tool-by-tool without touching the pipeline.
//
//   Codex     ~/.codex/config.toml ([mcp_servers.<name>]), AGENTS.md   (needs parse.TOML)
//   Gemini    ~/.gemini/settings.json (mcpServers)
//   OpenCode  opencode.json (project), ~/.config/opencode/ (mcp block)

// Codex discovers OpenAI Codex CLI MCP servers. Not yet implemented.
type Codex struct{}

// Tool returns the canonical tool id.
func (Codex) Tool() string { return "codex" }

// Discover satisfies ports.Discoverer (currently a no-op).
func (Codex) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	return nil, nil
}

// Gemini discovers Gemini CLI MCP servers. Not yet implemented.
type Gemini struct{}

// Tool returns the canonical tool id.
func (Gemini) Tool() string { return "gemini" }

// Discover satisfies ports.Discoverer (currently a no-op).
func (Gemini) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	return nil, nil
}

// OpenCode discovers OpenCode MCP servers. Not yet implemented.
type OpenCode struct{}

// Tool returns the canonical tool id.
func (OpenCode) Tool() string { return "opencode" }

// Discover satisfies ports.Discoverer (currently a no-op).
func (OpenCode) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	return nil, nil
}
