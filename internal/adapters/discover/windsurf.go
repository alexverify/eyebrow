package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Windsurf discovers Windsurf (Codeium) MCP servers and project rules. The MCP
// config is user-level at ~/.codeium/windsurf/mcp_config.json; rules live in a
// project's .windsurf/rules/*.md.
type Windsurf struct {
	home string
}

// NewWindsurf constructs the discoverer.
func NewWindsurf() *Windsurf {
	home, _ := os.UserHomeDir()
	return &Windsurf{home: home}
}

// Tool returns the canonical tool id.
func (w *Windsurf) Tool() string { return "windsurf" }

// Discover satisfies ports.Discoverer.
func (w *Windsurf) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, rulesFromDir(w.Tool(), filepath.Join(sc.Path, ".windsurf", "rules"), sc.String(), ".md")...)
		case "global":
			if w.home != "" {
				out = append(out, mcpServersFromConfig(w.Tool(), filepath.Join(w.home, ".codeium", "windsurf", "mcp_config.json"), "global", parse.JSON)...)
			}
		}
	}
	return out, nil
}
