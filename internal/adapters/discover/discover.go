// Package discover walks tool configurations and normalizes every skill, MCP
// server, plugin, hook, rule, and context file into the domain Artifact model.
//
// Each supported tool has its own discoverer; Multi aggregates them. Adding a
// tool is a one-line change to Default — the seam that keeps discovery
// resilient as tools and their config layouts drift between versions.
package discover

import (
	"context"
	"sort"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
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

// Tools lists the tool names of the composed discoverers that declare one,
// sorted and de-duplicated. Discoverers without a Tool method (the declared
// manifest reader) are skipped.
func (m *Multi) Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range m.tools {
		named, ok := t.(interface{ Tool() string })
		if !ok {
			continue
		}
		name := named.Tool()
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Default returns discoverers for every supported tool, led by the declared-layout
// adapter (eyebrow.discover.json), then Claude Code, Claude Desktop, Cursor,
// Gemini, OpenCode, Codex, Windsurf, GitHub Copilot CLI, Visual Studio Code, Zed,
// Kiro, Qwen Code, Kimi CLI, and Factory Droid — plus AEON (inert unless a scanned
// project root carries an aeon.yml marker) and the AgentOS registry, which is inert
// unless a "registry" scope is supplied, so ordinary local scans stay offline.
func Default() *Multi {
	return NewMulti(
		NewDeclared(),
		NewAgentOS(),
		NewClaudeCode(),
		NewClaudeDesktop(),
		NewCursor(),
		NewGemini(),
		NewOpenCode(),
		NewCodex(),
		NewWindsurf(),
		NewCopilot(),
		NewVSCode(),
		NewZed(),
		NewKiro(),
		NewQwen(),
		NewKimi(),
		NewDroid(),
		NewOpenClaude(),
		NewOpenClaudeRegistry(),
		NewAeon(),
		NewSkillsLock(),
	)
}
