package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/assay/internal/adapters/parse"
	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/domain/artifact"
)

// Codex discovers OpenAI Codex CLI MCP servers from config.toml
// (~/.codex/config.toml global, .codex/config.toml project) and the AGENTS.md
// context file. The config is TOML, parsed via parse.TOML.
type Codex struct {
	home string
}

// NewCodex constructs the discoverer.
func NewCodex() *Codex {
	home, _ := os.UserHomeDir()
	return &Codex{home: home}
}

// Tool returns the canonical tool id.
func (c *Codex) Tool() string { return "codex" }

// Discover satisfies ports.Discoverer.
func (c *Codex) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, c.fromConfig(filepath.Join(sc.Path, ".codex", "config.toml"), sc.String())...)
			out = append(out, fileArtifact(c.Tool(), filepath.Join(sc.Path, "AGENTS.md"), sc.String(), artifact.TypeContext, "AGENTS")...)
		case "global":
			if c.home != "" {
				out = append(out, c.fromConfig(filepath.Join(c.home, ".codex", "config.toml"), "global")...)
			}
		}
	}
	return out, nil
}

type codexMCP struct {
	Command string            `toml:"command"`
	Args    []string          `toml:"args"`
	Env     map[string]string `toml:"env"`
	URL     string            `toml:"url"`
}

type codexConfig struct {
	MCPServers map[string]codexMCP `toml:"mcp_servers"`
}

func (c *Codex) fromConfig(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg codexConfig
	if err := parse.TOML(b, &cfg); err != nil {
		return nil
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		baseDir = filepath.Dir(path)
	}
	out := make([]artifact.Artifact, 0, len(cfg.MCPServers))
	for name, m := range cfg.MCPServers {
		decl := mcpDecl{Command: m.Command, Args: m.Args, Env: m.Env, URL: m.URL}
		a := artifact.Artifact{
			Tool:           c.Tool(),
			Scope:          scope,
			Type:           artifact.TypeMCPServer,
			Name:           name,
			Source:         sourceFromMCP(decl, baseDir),
			Capabilities:   capabilitiesFromMCP(decl),
			DiscoveredFrom: path,
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}
