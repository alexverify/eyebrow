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
)

// ai17zExt is the extension AI17Z uses for an exported agent package: a
// shared persona (agent, avatar, and learned state) that users hand to each
// other. A persona edited in transit changes what an agent says under
// someone's name, so each package is treated as its own artifact — hashed,
// analyzed, and locked like any other.
const ai17zExt = ".ai17z-agent"

// ai17zMaxDepth bounds the walk to at most 3 directories below the scope
// root, keeping discovery bounded on large trees without a config knob.
const ai17zMaxDepth = 3

// ai17zSkipDirs are directories discovery never descends into: dependency
// and vendor trees an agent package would never live in. This mirrors
// isVendorDir in internal/adapters/analyze/native.go, copied rather than
// imported since that helper is unexported and analyze sits on the far side
// of discover in the dependency graph.
var ai17zSkipDirs = map[string]bool{
	"node_modules":     true,
	"bower_components": true,
	".venv":            true,
	"venv":             true,
	"site-packages":    true,
	"__pycache__":      true,
	"vendor":           true,
	"dist":             true,
	"build":            true,
}

// AI17Z discovers AI17Z agent packages (*.ai17z-agent) under a project root.
type AI17Z struct{}

// NewAI17Z constructs the AI17Z agent-package discoverer.
func NewAI17Z() *AI17Z { return &AI17Z{} }

// Tool returns the canonical tool id.
func (a *AI17Z) Tool() string { return "ai17z" }

// Discover satisfies ports.Discoverer. It walks each project scope's root to
// a bounded depth, skipping hidden and vendor directories, and turns every
// *.ai17z-agent file that parses as a JSON object into one subagent artifact.
// The global scope discovers nothing: a shared persona is a project-local
// file, not something installed once per user.
func (a *AI17Z) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		out = append(out, a.discoverProject(sc)...)
	}
	return out, nil
}

func (a *AI17Z) discoverProject(sc ports.Scope) []artifact.Artifact {
	root := sc.Path
	scope := sc.String()
	var out []artifact.Artifact

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip it, keep walking
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		// depth is how many directories under root this entry's parent chain
		// crosses: 0 for a direct child of root, 1 for a grandchild, and so
		// on — the number of "/" separators in the relative path.
		depth := strings.Count(relSlash, "/")
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") || ai17zSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			// A directory at depth >= ai17zMaxDepth is itself the
			// (ai17zMaxDepth+1)th directory below root; don't descend into it.
			if depth >= ai17zMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if depth > ai17zMaxDepth {
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ai17zExt) {
			return nil
		}
		// Name is the path relative to the scope root (forward slashes),
		// not the bare file name: MakeID hashes tool/scope/type/name but
		// never the path, so two packages sharing a base name in different
		// directories (root/night-owl.ai17z-agent and
		// root/personas/night-owl.ai17z-agent) must still get distinct
		// names — and therefore distinct IDs — or lockfile.Compare silently
		// collapses one of them.
		name := strings.TrimSuffix(relSlash, ai17zExt)
		art, ok := ai17zArtifact(a.Tool(), path, scope, name)
		if ok {
			out = append(out, art)
		}
		return nil
	})

	return out
}

// ai17zArtifact builds the artifact for one candidate file, or reports ok=false
// when the content does not parse as a JSON object (a package edited into
// garbage, or a file that merely shares the extension by accident). name is
// the file's path relative to the scope root (forward slashes, extension
// stripped), which keeps same-named packages in different directories from
// colliding on ID (see the call site).
func ai17zArtifact(tool, path, scope, name string) (artifact.Artifact, bool) {
	b, err := os.ReadFile(path)
	if err != nil || !looksLikeJSONObject(b) {
		return artifact.Artifact{}, false
	}
	a := artifact.Artifact{
		Tool:           tool,
		Type:           artifact.TypeSubagent,
		Name:           name,
		Scope:          scope,
		Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: path},
		DiscoveredFrom: path,
	}
	a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
	return a, true
}

// looksLikeJSONObject reports whether b parses as JSON whose first non-space
// byte is '{', matching how the brief distinguishes a real package from a
// same-extension file that happens not to be one.
func looksLikeJSONObject(b []byte) bool {
	trimmed := strings.TrimSpace(string(b))
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	return json.Valid(b)
}
