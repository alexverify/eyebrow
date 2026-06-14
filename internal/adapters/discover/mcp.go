package discover

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/assay/internal/adapters/mcpconfig"
	"github.com/alexverify/assay/internal/domain/artifact"
)

// mcpDecl is one entry under an "mcpServers" config object.
type mcpDecl struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

type mcpConfig struct {
	MCPServers map[string]mcpDecl `json:"mcpServers"`
}

// mcpServersFromConfig parses a config file's mcpServers block into artifacts
// for the given tool/scope. A missing or unparseable file yields nothing (and
// no error): discovery stays tolerant. parseFn is the format reader (JSON/JSONC).
func mcpServersFromConfig(tool, path, scope string, parseFn func([]byte, any) error) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg mcpConfig
	if err := parseFn(b, &cfg); err != nil {
		return nil
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		baseDir = filepath.Dir(path)
	}
	out := make([]artifact.Artifact, 0, len(cfg.MCPServers))
	for name, decl := range cfg.MCPServers {
		decl = unshim(decl)
		a := artifact.Artifact{
			Tool:           tool,
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

// skillsFromDir discovers <root>/<name>/SKILL.md skill directories for a tool.
func skillsFromDir(tool, root, scope string) []artifact.Artifact {
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
		if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
			continue
		}
		a := artifact.Artifact{
			Tool:           tool,
			Scope:          scope,
			Type:           artifact.TypeSkill,
			Name:           e.Name(),
			Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: dir},
			DiscoveredFrom: filepath.Join(dir, "SKILL.md"),
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}

// rulesFromDir discovers rule files (e.g. Cursor's .cursor/rules/*.mdc) as
// rules artifacts, hashed by content via a local source.
func rulesFromDir(tool, root, scope, suffix string) []artifact.Artifact {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []artifact.Artifact
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		path := filepath.Join(root, e.Name())
		a := artifact.Artifact{
			Tool:           tool,
			Scope:          scope,
			Type:           artifact.TypeRules,
			Name:           strings.TrimSuffix(e.Name(), suffix),
			Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: path},
			DiscoveredFrom: path,
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}

// mdFilesFromDir discovers *.md files directly under root as artifacts of the
// given type (e.g. Claude Code subagents under .claude/agents).
func mdFilesFromDir(tool, root, scope string, typ artifact.Type) []artifact.Artifact {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []artifact.Artifact
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join(root, e.Name())
		a := artifact.Artifact{
			Tool:           tool,
			Scope:          scope,
			Type:           typ,
			Name:           strings.TrimSuffix(e.Name(), ".md"),
			Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: path},
			DiscoveredFrom: path,
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}

// fileArtifact builds a single local-file artifact if the file exists, else nil.
func fileArtifact(tool, path, scope string, typ artifact.Type, name string) []artifact.Artifact {
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		return nil
	}
	a := artifact.Artifact{
		Tool:           tool,
		Scope:          scope,
		Type:           typ,
		Name:           name,
		Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: path},
		DiscoveredFrom: path,
	}
	a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
	return []artifact.Artifact{a}
}

// unshim sees through `assay wrap`: a declaration routed via the
// mcp-shim is normalized back to the underlying server, so wrapping never
// changes the discovered artifact (and never reads as drift on verify).
func unshim(d mcpDecl) mcpDecl {
	if orig, ok := mcpconfig.UnwrapArgv(d.Args); ok {
		d.Command = orig[0]
		d.Args = orig[1:]
	}
	return d
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

func capabilitiesFromMCP(d mcpDecl) artifact.Capabilities {
	caps := artifact.Capabilities{Exec: d.Command != ""}
	if d.URL != "" {
		if u, err := url.Parse(d.URL); err == nil && u.Host != "" {
			caps.Network = []string{u.Host}
		}
	}
	return caps
}

func firstPackageArg(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

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

func isPathLike(s string) bool {
	return filepath.IsAbs(s) || strings.HasPrefix(s, ".") || strings.ContainsRune(s, '/')
}

func absUnder(baseDir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(baseDir, p)
}
