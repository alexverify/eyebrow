package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

func TestGeminiDiscoversMCPFromSettings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gemini", "settings.json"), `{
		"mcpServers": {
			"tools": { "command": "npx", "args": ["-y", "g-tools@2.1.0"] }
		}
	}`)

	g := NewGemini()
	if g.Tool() != "gemini" {
		t.Fatalf("Tool() = %q", g.Tool())
	}
	got, err := g.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["tools"].Source.Kind != artifact.SourceNPM || m["tools"].Source.Ref != "g-tools@2.1.0" {
		t.Errorf("tools server wrong: %+v", m["tools"].Source)
	}
	if m["tools"].Tool != "gemini" {
		t.Errorf("tool tag wrong: %q", m["tools"].Tool)
	}
}
