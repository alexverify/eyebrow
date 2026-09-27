package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Dir reports one folder as a single artifact, for `eyebrow check`: a package
// staged for install is scanned on its own, outside any tool's layout. The
// folder is a skill when it carries SKILL.md at its root and a plugin
// otherwise. It is never part of Default.
type Dir struct {
	root string
}

// NewDir constructs the single-folder discoverer.
func NewDir(root string) *Dir { return &Dir{root: root} }

// Tool returns the pseudo tool id recorded on the artifact.
func (d *Dir) Tool() string { return "check" }

// Discover satisfies ports.Discoverer. Scopes are ignored: the folder is the scope.
func (d *Dir) Discover(_ context.Context, _ []ports.Scope) ([]artifact.Artifact, error) {
	a := artifact.Artifact{
		Tool:           d.Tool(),
		Scope:          "check",
		Type:           artifact.TypePlugin,
		Name:           filepath.Base(d.root),
		Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: d.root},
		DiscoveredFrom: d.root,
	}
	if skillMd := filepath.Join(d.root, "SKILL.md"); exists(skillMd) {
		a.Type = artifact.TypeSkill
		a.DiscoveredFrom = skillMd
		a.Description = frontmatterDescription(skillMd)
	} else {
		for _, m := range []string{"openclaw.plugin.json", "package.json"} {
			if p := filepath.Join(d.root, m); exists(p) {
				a.DiscoveredFrom = p
				break
			}
		}
	}
	a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
	return []artifact.Artifact{a}, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
