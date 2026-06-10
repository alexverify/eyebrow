package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

func TestCodexDiscoversMCPFromTOMLAndContext(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".codex", "config.toml"), `
[mcp_servers.search]
command = "npx"
args = ["-y", "codex-search@1.2.3"]
env = { API_KEY = "secret" }

[mcp_servers.remote]
url = "https://api.example.com/mcp"
`)
	writeFile(t, filepath.Join(dir, "AGENTS.md"), "agent context\n")

	c := NewCodex()
	if c.Tool() != "codex" {
		t.Fatalf("Tool() = %q", c.Tool())
	}
	got, err := c.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["search"].Source.Kind != artifact.SourceNPM || m["search"].Source.Ref != "codex-search@1.2.3" {
		t.Errorf("search server wrong: %+v", m["search"].Source)
	}
	if m["search"].Source.Env["API_KEY"] != "<redacted>" {
		t.Errorf("secret env should be redacted: %+v", m["search"].Source.Env)
	}
	if m["remote"].Source.Kind != artifact.SourceURL {
		t.Errorf("remote server should be a url source: %+v", m["remote"].Source)
	}
	if m["AGENTS"].Type != artifact.TypeContext {
		t.Errorf("expected AGENTS.md as a context artifact: %+v", m["AGENTS"])
	}
	if m["search"].Tool != "codex" {
		t.Errorf("tool tag wrong: %q", m["search"].Tool)
	}
}
