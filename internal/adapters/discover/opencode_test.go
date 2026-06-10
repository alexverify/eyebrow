package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

func TestOpenCodeDiscoversLocalAndRemoteMCP(t *testing.T) {
	dir := t.TempDir()
	// OpenCode uses an "mcp" block with {type, command:[...]}, parsed as JSONC.
	writeFile(t, filepath.Join(dir, "opencode.json"), `{
		// opencode config
		"mcp": {
			"local-tool":  { "type": "local",  "command": ["npx", "-y", "oc@1.0.0"], "enabled": true },
			"remote-tool": { "type": "remote", "url": "https://api.example.com/mcp" },
		}
	}`)

	o := NewOpenCode()
	if o.Tool() != "opencode" {
		t.Fatalf("Tool() = %q", o.Tool())
	}
	got, err := o.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["local-tool"].Source.Kind != artifact.SourceNPM || m["local-tool"].Source.Ref != "oc@1.0.0" {
		t.Errorf("local-tool wrong: %+v", m["local-tool"].Source)
	}
	if m["remote-tool"].Source.Kind != artifact.SourceURL {
		t.Errorf("remote-tool should be a url source: %+v", m["remote-tool"].Source)
	}
	if m["local-tool"].Tool != "opencode" {
		t.Errorf("tool tag wrong: %q", m["local-tool"].Tool)
	}
}
