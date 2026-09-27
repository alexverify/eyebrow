package discover

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// maxPackageJSONBytes bounds the package.json Dir reads for a name.
const maxPackageJSONBytes = 1 << 20

// Dir reports one folder as a single artifact, for `eyebrow check`: a package
// staged for install is scanned on its own, outside any tool's layout. The
// folder is a skill when it carries SKILL.md at its root and a plugin
// otherwise. It is never part of Default.
//
// The folder is hostile input. Dir opens only regular files: a SKILL.md or
// manifest that is a symlink, a named pipe or a directory is reported as
// CHECK-UNSAFE-ENTRY and never read.
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
		Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: d.root},
		DiscoveredFrom: d.root,
	}
	var name string
	skillMd := filepath.Join(d.root, "SKILL.md")
	if info, err := os.Lstat(skillMd); err == nil {
		a.Type = artifact.TypeSkill
		a.DiscoveredFrom = skillMd
		if info.Mode().IsRegular() {
			a.Description = frontmatterDescription(skillMd)
			name = frontmatterValue(skillMd, "name")
		} else {
			a.Findings = append(a.Findings, finding.UnsafeEntry("SKILL.md", entryKind(info.Mode())))
		}
	} else {
		for _, m := range []string{"openclaw.plugin.json", "package.json"} {
			p := filepath.Join(d.root, m)
			info, err := os.Lstat(p)
			if err != nil {
				continue
			}
			a.DiscoveredFrom = p
			if !info.Mode().IsRegular() {
				a.Findings = append(a.Findings, finding.UnsafeEntry(m, entryKind(info.Mode())))
			}
			break
		}
	}
	if name == "" {
		name = packageJSONName(filepath.Join(d.root, "package.json"))
	}
	if name == "" {
		name = filepath.Base(d.root)
	}
	a.Name = name
	a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
	return []artifact.Artifact{a}, nil
}

// packageJSONName returns package.json's top-level "name", or "" when the
// file is missing, not a regular file, larger than 1 MiB, or not valid JSON.
func packageJSONName(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPackageJSONBytes {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pkg struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &pkg) != nil {
		return ""
	}
	return pkg.Name
}

// entryKind names a non-regular entry for a CHECK-UNSAFE-ENTRY finding.
func entryKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	default:
		return "named pipe or device"
	}
}
