package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/domain/artifact"
)

func TestCursorDiscoversMCPWithJSONCAndRules(t *testing.T) {
	dir := t.TempDir()
	// Cursor mcp.json with a comment and a trailing comma (JSONC).
	writeFile(t, filepath.Join(dir, ".cursor", "mcp.json"), `{
		// cursor servers
		"mcpServers": {
			"search": { "url": "https://api.example.com/sse" },
		}
	}`)
	writeFile(t, filepath.Join(dir, ".cursor", "rules", "style.mdc"), "always use tabs\n")

	c := NewCursor()
	got, err := c.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if c.Tool() != "cursor" {
		t.Errorf("Tool() = %q", c.Tool())
	}
	if m["search"].Type != artifact.TypeMCPServer || m["search"].Source.Kind != artifact.SourceURL {
		t.Errorf("search server wrong: %+v", m["search"])
	}
	if m["search"].Tool != "cursor" {
		t.Errorf("tool tag wrong: %q", m["search"].Tool)
	}
	if m["style"].Type != artifact.TypeRules {
		t.Errorf("expected a rules artifact for style.mdc: %+v", m)
	}
}
