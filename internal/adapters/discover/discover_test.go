package discover

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
)

func TestDefaultDiscoversAcrossTools(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	// NewKimi resolves its user-scope path from the home dir at construction, so
	// pin the home before Default() builds the discoverers. os.UserHomeDir reads
	// USERPROFILE on Windows and HOME elsewhere; set both.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// One project carrying configs for the project-scoped tools, plus a
	// user-scope config for launch-scoped kimi.
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"cc":{"command":"npx","args":["-y","cc@1.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, ".cursor", "mcp.json"), `{"mcpServers":{"cur":{"url":"https://x/sse"}}}`)
	writeFile(t, filepath.Join(dir, ".gemini", "settings.json"), `{"mcpServers":{"gem":{"command":"npx","args":["-y","gem@2.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, "opencode.json"), `{"mcp":{"oc":{"type":"local","command":["npx","-y","oc@1.0.0"]}}}`)
	writeFile(t, filepath.Join(dir, ".codex", "config.toml"), "[mcp_servers.cx]\ncommand = \"npx\"\nargs = [\"-y\", \"cx@1.0.0\"]\n")
	writeFile(t, filepath.Join(dir, ".qwen", "settings.json"), `{"mcpServers":{"qw":{"command":"/abs/vex-mcp","args":["--project","p"]}}}`)
	writeFile(t, filepath.Join(dir, ".factory", "mcp.json"), `{"mcpServers":{"dr":{"command":"/abs/vex-mcp","args":["--project","p"]}}}`)
	writeFile(t, filepath.Join(home, ".kimi", "mcp.json"), `{"mcpServers":{"km":{"command":"/abs/vex-mcp","args":["--project","p"]}}}`)

	got, err := Default().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}, {Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	tools := map[string]bool{}
	for _, a := range got {
		tools[a.Tool] = true
	}
	for _, want := range []string{"claude-code", "cursor", "gemini", "opencode", "codex", "qwen-code", "kimi", "droid"} {
		if !tools[want] {
			t.Errorf("Default() did not discover tool %q; tools seen: %v", want, tools)
		}
	}
}

// A manifest owns its root: the same skills/ tree must not also be reported
// by the AEON adapter, or every skill would appear twice under two tool ids.
func TestDefaultReportsManifestCatalogOnce(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"my-catalog","skills":["skills/*"]}`)
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "---\nname: a\n---\n")

	got, err := Default().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var tools []string
	for _, a := range got {
		if a.Name == "a" {
			tools = append(tools, a.Tool)
		}
	}
	if len(tools) != 1 || tools[0] != "my-catalog" {
		t.Errorf("skill a reported under tools %v, want exactly [my-catalog]", tools)
	}
}

func TestDefaultToolsIncludesClaudeCodeAndIsSorted(t *testing.T) {
	tools := Default().Tools()
	if len(tools) == 0 {
		t.Fatal("no tools listed")
	}
	if !sort.StringsAreSorted(tools) {
		t.Fatalf("not sorted: %v", tools)
	}
	found := false
	for i, name := range tools {
		if name == "claude-code" {
			found = true
		}
		if i > 0 && tools[i-1] == name {
			t.Fatalf("duplicate %q", name)
		}
	}
	if !found {
		t.Fatalf("claude-code missing from %v", tools)
	}
	foundAI17Z := false
	for _, name := range tools {
		if name == "ai17z" {
			foundAI17Z = true
		}
	}
	if !foundAI17Z {
		t.Fatalf("ai17z missing from %v", tools)
	}
}
