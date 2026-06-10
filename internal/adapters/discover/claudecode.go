package discover

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/agentguard/internal/adapters/parse"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// ClaudeCode discovers Claude Code MCP servers and skills.
//
// It is intentionally narrow for the MVP — project .mcp.json and the skills
// directory — and tolerant of missing files. Hooks, subagents, plugins, and
// global settings.json parsing are documented extension points handled by the
// same Source/Artifact model.
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
			out = append(out, c.fromMCPConfig(filepath.Join(sc.Path, ".mcp.json"), sc.String())...)
			out = append(out, c.fromSkills(filepath.Join(sc.Path, ".claude", "skills"), sc.String())...)
		case "global":
			if c.home != "" {
				out = append(out, c.fromMCPConfig(filepath.Join(c.home, ".claude.json"), "global")...)
				out = append(out, c.fromSkills(filepath.Join(c.home, ".claude", "skills"), "global")...)
			}
		}
	}
	return out, nil
}

type mcpDecl struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

type mcpConfig struct {
	MCPServers map[string]mcpDecl `json:"mcpServers"`
}

// fromMCPConfig parses a JSON config's mcpServers block. A missing file yields
// no artifacts and no error.
func (c *ClaudeCode) fromMCPConfig(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg mcpConfig
	if err := parse.JSON(b, &cfg); err != nil {
		return nil // tolerant: a malformed config should not abort discovery
	}

	// Local paths in a config are relative to the config file's directory,
	// not the process working directory. Resolve against it so artifacts are
	// self-contained and portable.
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		baseDir = filepath.Dir(path)
	}

	out := make([]artifact.Artifact, 0, len(cfg.MCPServers))
	for name, decl := range cfg.MCPServers {
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

// fromSkills discovers <root>/<name>/SKILL.md skill directories.
func (c *ClaudeCode) fromSkills(root, scope string) []artifact.Artifact {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []artifact.Artifact
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		skillMd := filepath.Join(dir, "SKILL.md")
		if _, err := os.Stat(skillMd); err != nil {
			continue
		}
		a := artifact.Artifact{
			Tool:           c.Tool(),
			Scope:          scope,
			Type:           artifact.TypeSkill,
			Name:           e.Name(),
			Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: dir},
			DiscoveredFrom: skillMd,
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}

// sourceFromMCP maps an MCP server declaration to a Source, inferring the kind.
// baseDir is the directory of the config file, used to absolutize local paths.
func sourceFromMCP(d mcpDecl, baseDir string) artifact.Source {
	switch {
	case d.URL != "":
		return artifact.Source{Kind: artifact.SourceURL, Ref: d.URL, Env: redactSecretEnv(d.Env)}
	case d.Command == "npx" || d.Command == "npm":
		return artifact.Source{
			Kind:    artifact.SourceNPM,
			Ref:     firstPackageArg(d.Args),
			Command: d.Command,
			Args:    d.Args,
			Env:     redactSecretEnv(d.Env),
		}
	case d.Command != "":
		// A path-like command points at local code we can hash; a bare command
		// (e.g. "node") is a PATH binary whose real code lives in its args —
		// resolving that interpreter+script case is a documented future step.
		ref := d.Command
		if isPathLike(d.Command) {
			ref = absUnder(baseDir, d.Command)
		}
		return artifact.Source{
			Kind:    artifact.SourceLocal,
			Ref:     ref,
			Command: d.Command,
			Args:    d.Args,
			Env:     redactSecretEnv(d.Env),
		}
	default:
		return artifact.Source{Kind: artifact.SourceInline}
	}
}

// isPathLike reports whether s denotes a filesystem path rather than a bare
// command name resolved via PATH.
func isPathLike(s string) bool {
	return filepath.IsAbs(s) || strings.HasPrefix(s, ".") || strings.ContainsRune(s, '/')
}

// absUnder joins a (possibly relative) path to baseDir, returning an absolute,
// cleaned path.
func absUnder(baseDir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(baseDir, p)
}

func capabilitiesFromMCP(d mcpDecl) artifact.Capabilities {
	caps := artifact.Capabilities{Exec: d.Command != ""}
	if d.URL != "" {
		if u, err := url.Parse(d.URL); err == nil && u.Host != "" {
			caps.Network = []string{u.Host}
		}
	}
	return caps
}

// firstPackageArg returns the first non-flag argument, i.e. the npm package
// spec in `npx -y some-mcp@1.2.3`.
func firstPackageArg(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// redactSecretEnv keeps only environment keys whose names suggest secrets,
// recording the key with a redacted value so the inventory flags exposure
// without ever persisting the secret itself.
func redactSecretEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	var out map[string]string
	for k := range env {
		if looksSecretKey(k) {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = "<redacted>"
		}
	}
	return out
}

func looksSecretKey(k string) bool {
	u := strings.ToUpper(k)
	for _, needle := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "API"} {
		if strings.Contains(u, needle) {
			return true
		}
	}
	return false
}
