package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/agentguard/internal/adapters/parse"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// Gemini discovers Gemini CLI MCP servers from settings.json
// (~/.gemini/settings.json global, .gemini/settings.json project).
type Gemini struct {
	home string
}

// NewGemini constructs the discoverer.
func NewGemini() *Gemini {
	home, _ := os.UserHomeDir()
	return &Gemini{home: home}
}

// Tool returns the canonical tool id.
func (g *Gemini) Tool() string { return "gemini" }

// Discover satisfies ports.Discoverer.
func (g *Gemini) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, mcpServersFromConfig(g.Tool(), filepath.Join(sc.Path, ".gemini", "settings.json"), sc.String(), parse.JSON)...)
		case "global":
			if g.home != "" {
				out = append(out, mcpServersFromConfig(g.Tool(), filepath.Join(g.home, ".gemini", "settings.json"), "global", parse.JSON)...)
			}
		}
	}
	return out, nil
}
