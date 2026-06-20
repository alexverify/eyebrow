package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestWindsurfDiscoversGlobalMCPAndProjectRules(t *testing.T) {
	home := t.TempDir()
	proj := t.TempDir()
	writeFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{
  "mcpServers": {"ws-tool": {"command": "node", "args": ["s.js"]}}
}`)
	writeFile(t, filepath.Join(proj, ".windsurf", "rules", "style.md"), "# rules\nbe careful\n")

	d := &Windsurf{home: home}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	if a, ok := byName["ws-tool"]; !ok || a.Type != artifact.TypeMCPServer || a.Tool != "windsurf" {
		t.Errorf("windsurf MCP server not discovered: %+v", arts)
	}
	if a, ok := byName["style"]; !ok || a.Type != artifact.TypeRules {
		t.Errorf("windsurf project rule not discovered: %+v", arts)
	}
}

func TestCopilotDiscoversMCP(t *testing.T) {
	home := t.TempDir()
	proj := t.TempDir()
	writeFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), `{
  "mcpServers": {"gh-global": {"command": "npx", "args": ["-y", "pkg"]}}
}`)
	writeFile(t, filepath.Join(proj, ".github", "copilot", "mcp-config.json"), `{
  "mcpServers": {"gh-project": {"command": "./srv"}}
}`)

	d := &Copilot{home: home}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	for _, name := range []string{"gh-global", "gh-project"} {
		if a, ok := byName[name]; !ok || a.Tool != "copilot-cli" {
			t.Errorf("copilot server %q not discovered: %+v", name, arts)
		}
	}
}
