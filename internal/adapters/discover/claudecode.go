package discover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexverify/agentguard/internal/adapters/parse"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// ClaudeCode discovers Claude Code MCP servers and skills.
type ClaudeCode struct {
	home string
}

// NewClaudeCode constructs the discoverer, resolving the user's home directory
// for global-scope lookups.
func NewClaudeCode() *ClaudeCode {
	home, _ := os.UserHomeDir()
	return &ClaudeCode{home: home}
}

// Tool returns the canonical tool id.
func (c *ClaudeCode) Tool() string { return "claude-code" }

// Discover satisfies ports.Discoverer.
func (c *ClaudeCode) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			dot := filepath.Join(sc.Path, ".claude")
			out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(sc.Path, ".mcp.json"), sc.String(), parse.JSON)...)
			out = append(out, skillsFromDir(c.Tool(), filepath.Join(dot, "skills"), sc.String())...)
			out = append(out, mdFilesFromDir(c.Tool(), filepath.Join(dot, "agents"), sc.String(), artifact.TypeSubagent)...)
			out = append(out, c.hooksFromSettings(filepath.Join(dot, "settings.json"), sc.String())...)
			out = append(out, c.hooksFromSettings(filepath.Join(dot, "settings.local.json"), sc.String())...)
			out = append(out, fileArtifact(c.Tool(), filepath.Join(sc.Path, "CLAUDE.md"), sc.String(), artifact.TypeContext, "CLAUDE.md")...)
		case "global":
			if c.home != "" {
				dot := filepath.Join(c.home, ".claude")
				out = append(out, mcpServersFromConfig(c.Tool(), filepath.Join(c.home, ".claude.json"), "global", parse.JSON)...)
				out = append(out, skillsFromDir(c.Tool(), filepath.Join(dot, "skills"), "global")...)
				out = append(out, mdFilesFromDir(c.Tool(), filepath.Join(dot, "agents"), "global", artifact.TypeSubagent)...)
				out = append(out, c.hooksFromSettings(filepath.Join(dot, "settings.json"), "global")...)
				out = append(out, fileArtifact(c.Tool(), filepath.Join(dot, "CLAUDE.md"), "global", artifact.TypeContext, "CLAUDE.md")...)
			}
		}
	}
	return out, nil
}

// hookEntry/hookGroup/settingsFile mirror the relevant shape of a Claude Code
// settings.json. Hooks run arbitrary shell on lifecycle events, so each command
// is captured as an inline artifact — content-hashed for drift detection.
type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type hookGroup struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

type settingsFile struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

// hooksFromSettings extracts command hooks from a settings file. A missing or
// unparseable file yields nothing.
func (c *ClaudeCode) hooksFromSettings(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var sf settingsFile
	if err := parse.JSON(b, &sf); err != nil {
		return nil
	}
	var out []artifact.Artifact
	for event, groups := range sf.Hooks {
		for gi, g := range groups {
			for hi, h := range g.Hooks {
				if h.Type != "command" || h.Command == "" {
					continue
				}
				a := artifact.Artifact{
					Tool:           c.Tool(),
					Scope:          scope,
					Type:           artifact.TypeHook,
					Name:           fmt.Sprintf("%s/%s#%d.%d", event, g.Matcher, gi, hi),
					Source:         artifact.Source{Kind: artifact.SourceInline, Ref: h.Command},
					Capabilities:   artifact.Capabilities{Exec: true},
					DiscoveredFrom: path,
				}
				a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
				out = append(out, a)
			}
		}
	}
	return out
}
