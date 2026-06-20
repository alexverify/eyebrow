package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// OpenCode discovers MCP servers from opencode.json (project) and
// ~/.config/opencode/opencode.json (global). OpenCode uses an "mcp" block whose
// entries differ from the mcpServers shape — {type, command:[...], url} — so it
// is mapped onto the shared mcpDecl before reusing sourceFromMCP. Configs are
// parsed as JSONC.
type OpenCode struct {
	home string
}

// NewOpenCode constructs the discoverer.
func NewOpenCode() *OpenCode {
	home, _ := os.UserHomeDir()
	return &OpenCode{home: home}
}

// Tool returns the canonical tool id.
func (o *OpenCode) Tool() string { return "opencode" }

// Discover satisfies ports.Discoverer.
func (o *OpenCode) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, o.fromConfig(filepath.Join(sc.Path, "opencode.json"), sc.String())...)
		case "global":
			if o.home != "" {
				out = append(out, o.fromConfig(filepath.Join(o.home, ".config", "opencode", "opencode.json"), "global")...)
			}
		}
	}
	return out, nil
}

type openCodeMCP struct {
	Type        string            `json:"type"`
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
	URL         string            `json:"url"`
}

type openCodeConfig struct {
	MCP map[string]openCodeMCP `json:"mcp"`
}

func (o *OpenCode) fromConfig(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg openCodeConfig
	if err := parse.JSONC(b, &cfg); err != nil {
		return nil
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		baseDir = filepath.Dir(path)
	}
	out := make([]artifact.Artifact, 0, len(cfg.MCP))
	for name, m := range cfg.MCP {
		decl := mcpDecl{Env: m.Environment, URL: m.URL}
		if len(m.Command) > 0 {
			decl.Command = m.Command[0]
			decl.Args = m.Command[1:]
		}
		a := artifact.Artifact{
			Tool:           o.Tool(),
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
