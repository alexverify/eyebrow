package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestAI17ZDiscoversPackages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "night-owl.ai17z-agent"),
		`{"agent":{"name":"night-owl"},"avatar":{},"learned":[],"sha256":"abc"}`)
	writeFile(t, filepath.Join(dir, "day-owl.ai17z-agent"),
		`{"agent":{"name":"day-owl"},"avatar":{},"learned":[],"sha256":"def"}`)
	writeFile(t, filepath.Join(dir, "personas", "moonwatcher.ai17z-agent"),
		`{"agent":{"name":"moonwatcher"},"avatar":{},"learned":[],"sha256":"ghi"}`)
	// Not valid JSON — must be skipped.
	writeFile(t, filepath.Join(dir, "notes.ai17z-agent"), "these are not json notes")
	// Wrong extension — must be ignored entirely.
	writeFile(t, filepath.Join(dir, "README.md"), "# hi\n")

	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("discovered %d artifacts, want 3: %+v", len(got), got)
	}

	m := byName(got)
	for _, name := range []string{"night-owl", "day-owl", "personas/moonwatcher"} {
		a, ok := m[name]
		if !ok {
			t.Fatalf("missing artifact %q in %+v", name, got)
		}
		if a.Tool != "ai17z" {
			t.Errorf("%s: tool = %q, want ai17z", name, a.Tool)
		}
		if a.Type != artifact.TypeSubagent {
			t.Errorf("%s: type = %q, want subagent", name, a.Type)
		}
		if a.Source.Kind != artifact.SourceLocal {
			t.Errorf("%s: source kind = %q, want local", name, a.Source.Kind)
		}
		if a.Source.Ref == "" {
			t.Errorf("%s: source ref empty", name)
		}
		if a.DiscoveredFrom == "" {
			t.Errorf("%s: DiscoveredFrom empty", name)
		}
		if a.ID == "" {
			t.Errorf("%s: ID empty", name)
		}
	}

	ids := map[string]bool{}
	for _, a := range got {
		if ids[a.ID] {
			t.Fatalf("duplicate ID %q across %+v", a.ID, got)
		}
		ids[a.ID] = true
	}
}

func TestAI17ZSkipsHiddenAndVendorDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "hidden.ai17z-agent"), `{"agent":{"name":"hidden"}}`)
	writeFile(t, filepath.Join(dir, "node_modules", "buried.ai17z-agent"), `{"agent":{"name":"buried"}}`)
	writeFile(t, filepath.Join(dir, "visible.ai17z-agent"), `{"agent":{"name":"visible"}}`)

	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d artifacts, want 1 (hidden/vendor dirs must be skipped): %+v", len(got), got)
	}
	if got[0].Name != "visible" {
		t.Fatalf("got %q, want visible", got[0].Name)
	}
}

// artifact.MakeID hashes tool, scope, type, and name — never the path — so
// two packages sharing a base name in different directories must get
// distinct Names (and therefore distinct IDs), or lockfile.Compare silently
// collapses one of them.
func TestAI17ZSameFileNameInTwoDirectoriesGetsTwoIDs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "night-owl.ai17z-agent"),
		`{"agent":{"name":"night-owl","home":"root"}}`)
	writeFile(t, filepath.Join(dir, "personas", "night-owl.ai17z-agent"),
		`{"agent":{"name":"night-owl","home":"personas"}}`)

	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("discovered %d artifacts, want 2: %+v", len(got), got)
	}

	m := byName(got)
	root, ok := m["night-owl"]
	if !ok {
		t.Fatalf("missing root-level artifact named night-owl in %+v", got)
	}
	nested, ok := m["personas/night-owl"]
	if !ok {
		t.Fatalf("missing nested artifact named personas/night-owl in %+v", got)
	}
	if root.ID == nested.ID {
		t.Fatalf("root and nested night-owl packages share an ID %q, want distinct IDs", root.ID)
	}
}

// The walk is bounded to at most 3 directories below the scope root: a
// package inside the 3rd-level directory is found, one inside the 4th is
// not.
func TestAI17ZDepthBoundary(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a", "b", "c", "x.ai17z-agent"), `{"agent":{"name":"x"}}`)
	writeFile(t, filepath.Join(dir, "a", "b", "c", "d", "y.ai17z-agent"), `{"agent":{"name":"y"}}`)

	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d artifacts, want 1: %+v", len(got), got)
	}
	if got[0].Name != "a/b/c/x" {
		t.Fatalf("got name %q, want a/b/c/x", got[0].Name)
	}
}

func TestAI17ZIgnoresGlobalScope(t *testing.T) {
	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("global scope should discover nothing, got %+v", got)
	}
}
