package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/agentguard/internal/adapters/parse"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// Cursor discovers Cursor MCP servers (~/.cursor/mcp.json, .cursor/mcp.json)
// and project rules (.cursor/rules/*.mdc). Cursor configs may contain comments,
// so they are parsed as JSONC.
type Cursor struct {
	home string
}

// NewCursor constructs the discoverer.
func NewCursor() *Cursor {
	home, _ := os.UserHomeDir()
	return &Cursor{home: home}
}

// Tool returns the canonical tool id.
func (c *Cursor) Tool() string { return "cursor" }

// Discover satisfies ports.Discoverer.
func (c *Cursor) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(sc.Path, ".cursor", "mcp.json"), sc.String(), parse.JSONC)...)
			out = append(out, rulesFromDir(c.Tool(), filepath.Join(sc.Path, ".cursor", "rules"), sc.String(), ".mdc")...)
		case "global":
			if c.home != "" {
				out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(c.home, ".cursor", "mcp.json"), "global", parse.JSONC)...)
			}
		}
	}
	return out, nil
}
