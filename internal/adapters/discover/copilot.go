package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Copilot discovers GitHub Copilot CLI MCP servers. The standalone CLI stores
// its MCP config at ~/.copilot/mcp-config.json; a project may pin one under
// .github/copilot/mcp-config.json.
type Copilot struct {
	home string
}

// NewCopilot constructs the discoverer.
func NewCopilot() *Copilot {
	home, _ := os.UserHomeDir()
	return &Copilot{home: home}
}

// Tool returns the canonical tool id.
func (c *Copilot) Tool() string { return "copilot-cli" }

// Discover satisfies ports.Discoverer.
func (c *Copilot) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(sc.Path, ".github", "copilot", "mcp-config.json"), sc.String(), parse.JSON)...)
		case "global":
			if c.home != "" {
				out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(c.home, ".copilot", "mcp-config.json"), "global", parse.JSON)...)
			}
		}
	}
	return out, nil
}
