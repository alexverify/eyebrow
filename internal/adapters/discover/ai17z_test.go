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
	for _, name := range []string{"night-owl", "day-owl", "moonwatcher"} {
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

func TestAI17ZIgnoresGlobalScope(t *testing.T) {
	got, err := NewAI17Z().Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("global scope should discover nothing, got %+v", got)
	}
}
