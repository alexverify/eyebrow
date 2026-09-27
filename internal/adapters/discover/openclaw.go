package discover

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// OpenClaw discovers what the OpenClaw gateway loads. Global state lives in
// $OPENCLAW_STATE_DIR (default ~/.openclaw): openclaw.json (JSON5) declares
// MCP servers under mcp.servers and extra skill roots under
// skills.load.extraDirs; skills/ holds managed skills; extensions/ holds
// installed plugins, each a folder with an openclaw.plugin.json manifest.
// A project scope is OpenClaw's only when its root carries .openclaw/ or
// .clawhub/ — a plain skills/ folder belongs to other tools — and then its
// skills/ and .openclaw/extensions/ are read. Skills installed from ClawHub
// are pinned to the fingerprint in their .clawhub/origin.json.
type OpenClaw struct {
	home     string
	stateDir string
}

// NewOpenClaw constructs the discoverer.
func NewOpenClaw() *OpenClaw {
	home, _ := os.UserHomeDir()
	state := os.Getenv("OPENCLAW_STATE_DIR")
	if state == "" && home != "" {
		state = filepath.Join(home, ".openclaw")
	}
	return &OpenClaw{home: home, stateDir: state}
}

// Tool returns the canonical tool id.
func (o *OpenClaw) Tool() string { return "openclaw" }

// Discover satisfies ports.Discoverer.
func (o *OpenClaw) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "global":
			if o.stateDir != "" {
				out = append(out, o.global()...)
			}
		case "project":
			if sc.Path != "" && o.isOpenClawProject(sc.Path) {
				out = append(out, o.project(sc)...)
			}
		}
	}
	applyClawHubPins(out)
	return out, nil
}

type openClawConfig struct {
	MCP struct {
		Servers map[string]mcpDecl `json:"servers"`
	} `json:"mcp"`
	Skills struct {
		Load struct {
			ExtraDirs []string `json:"extraDirs"`
		} `json:"load"`
	} `json:"skills"`
}

func (o *OpenClaw) global() []artifact.Artifact {
	var out []artifact.Artifact
	cfgPath := filepath.Join(o.stateDir, "openclaw.json")
	if b, err := os.ReadFile(cfgPath); err == nil {
		var cfg openClawConfig
		if parse.JSON5(b, &cfg) == nil {
			out = append(out, mcpArtifactsFrom(o.Tool(), cfgPath, "global", cfg.MCP.Servers)...)
			for _, d := range cfg.Skills.Load.ExtraDirs {
				out = append(out, skillsFromDir(o.Tool(), o.expand(d, o.stateDir), "global")...)
			}
		}
	}
	out = append(out, skillsFromDir(o.Tool(), filepath.Join(o.stateDir, "skills"), "global")...)
	out = append(out, openClawPlugins(o.Tool(), filepath.Join(o.stateDir, "extensions"), "global")...)
	return out
}

func (o *OpenClaw) project(sc ports.Scope) []artifact.Artifact {
	out := skillsFromDir(o.Tool(), filepath.Join(sc.Path, "skills"), sc.String())
	return append(out, openClawPlugins(o.Tool(), filepath.Join(sc.Path, ".openclaw", "extensions"), sc.String())...)
}

func (o *OpenClaw) isOpenClawProject(root string) bool {
	for _, marker := range []string{".openclaw", ".clawhub"} {
		if info, err := os.Stat(filepath.Join(root, marker)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// expand resolves a configured path: a leading ~ is the home dir, and a
// relative path is taken against the config's directory.
func (o *OpenClaw) expand(p, base string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(o.home, p[1:])
	}
	if !filepath.IsAbs(p) {
		return filepath.Join(base, p)
	}
	return p
}

// openClawPlugins discovers <root>/<name>/openclaw.plugin.json plugin folders.
// The whole folder, node_modules included, is the plugin's content.
func openClawPlugins(tool, root, scope string) []artifact.Artifact {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []artifact.Artifact
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		manifest := filepath.Join(dir, "openclaw.plugin.json")
		b, err := os.ReadFile(manifest)
		if err != nil {
			continue
		}
		var m struct {
			Description string `json:"description"`
		}
		_ = parse.JSON5(b, &m)
		a := artifact.Artifact{
			Tool:           tool,
			Scope:          scope,
			Type:           artifact.TypePlugin,
			Name:           e.Name(),
			Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: dir},
			DiscoveredFrom: manifest,
			Description:    m.Description,
		}
		a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
		out = append(out, a)
	}
	return out
}
