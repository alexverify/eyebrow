package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/assay/internal/app/ports"
)

func TestDefaultDiscoversAcrossTools(t *testing.T) {
	dir := t.TempDir()
	// One project carrying configs for all five supported tools.
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"cc":{"command":"npx","args":["-y","cc@1.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, ".cursor", "mcp.json"), `{"mcpServers":{"cur":{"url":"https://x/sse"}}}`)
	writeFile(t, filepath.Join(dir, ".gemini", "settings.json"), `{"mcpServers":{"gem":{"command":"npx","args":["-y","gem@2.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, "opencode.json"), `{"mcp":{"oc":{"type":"local","command":["npx","-y","oc@1.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, ".codex", "config.toml"), "[mcp_servers.cx]\ncommand = \"npx\"\nargs = [\"-y\", \"cx@1.0.0\"]\n")

	got, err := Default().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	tools := map[string]bool{}
	for _, a := range got {
		tools[a.Tool] = true
	}
	for _, want := range []string{"claude-code", "cursor", "gemini", "opencode", "codex"} {
		if !tools[want] {
			t.Errorf("Default() did not discover tool %q; tools seen: %v", want, tools)
		}
	}
}
