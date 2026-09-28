package discover

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
// The folder is hostile input. Dir opens only regular files, reached directly
// or through a symlink that stays inside the folder. A SKILL.md or manifest
// that is any other kind of entry (a symlink out of the folder, a named pipe,
// a directory) is reported as CHECK-UNSAFE-ENTRY and never read.
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
		if readable, ok := d.regular(skillMd, info.Mode()); ok {
			a.Description = frontmatterDescription(readable)
			name = frontmatterValue(readable, "name")
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
			if _, ok := d.regular(p, info.Mode()); !ok {
				a.Findings = append(a.Findings, finding.UnsafeEntry(m, entryKind(info.Mode())))
			}
			break
		}
	}
	if name == "" {
		pkg := filepath.Join(d.root, "package.json")
		if info, err := os.Lstat(pkg); err == nil {
			if readable, ok := d.regular(pkg, info.Mode()); ok {
				name = packageJSONName(readable)
			}
		}
	}
	if name == "" {
		name = filepath.Base(d.root)
	}
	a.Name = name
	a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
	return []artifact.Artifact{a}, nil
}

// regular returns the path to open for an entry of the folder when it is a
// regular file, directly or through a symlink whose target stays inside the
// folder. Any other entry, including a symlink out of the folder or one that
// does not resolve, is not to be opened.
func (d *Dir) regular(path string, mode fs.FileMode) (string, bool) {
	if mode.IsRegular() {
		return path, true
	}
	if mode&fs.ModeSymlink == 0 {
		return "", false
	}
	root, err := filepath.EvalSymlinks(d.root)
	if err != nil {
		return "", false
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	ti, err := os.Lstat(target)
	if err != nil || !ti.Mode().IsRegular() {
		return "", false
	}
	return target, true
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
