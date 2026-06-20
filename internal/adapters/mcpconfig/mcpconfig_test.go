package mcpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const fixture = `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}
    },
    "local": {
      "command": "./server.sh"
    },
    "remote": {
      "type": "sse",
      "url": "https://mcp.example.com/sse"
    }
  },
  "otherTopLevel": {"keep": true}
}`

func writeFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".mcp.json")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWrapRewritesStdioServers(t *testing.T) {
	path := writeFixture(t)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n := cfg.Wrap("/usr/local/bin/assay"); n != 2 {
		t.Fatalf("Wrap changed %d servers, want 2 (remote must be skipped)", n)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	servers := serversByName(reloaded)

	gh := servers["github"]
	if !gh.Wrapped {
		t.Fatal("github must report wrapped")
	}
	if gh.Command != "npx" || !reflect.DeepEqual(gh.Args, []string{"-y", "@modelcontextprotocol/server-github"}) {
		t.Errorf("underlying command not preserved: %+v", gh)
	}
	if servers["remote"].Wrapped || !servers["remote"].Remote {
		t.Errorf("remote entry must stay untouched: %+v", servers["remote"])
	}

	// The raw file must point at the shim with the original argv after "--",
	// and preserve env and unknown fields verbatim.
	var raw map[string]any
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	entry := raw["mcpServers"].(map[string]any)["github"].(map[string]any)
	if entry["command"] != "/usr/local/bin/assay" {
		t.Errorf("command = %v", entry["command"])
	}
	wantArgs := []any{"mcp-shim", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"}
	if !reflect.DeepEqual(entry["args"], wantArgs) {
		t.Errorf("args = %v", entry["args"])
	}
	if env := entry["env"].(map[string]any); env["GITHUB_TOKEN"] != "${GITHUB_TOKEN}" {
		t.Errorf("env not preserved: %v", env)
	}
	if _, ok := raw["otherTopLevel"]; !ok {
		t.Error("unknown top-level fields must survive the rewrite")
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	path := writeFixture(t)
	cfg, _ := Load(path)
	cfg.Wrap("/bin/assay")
	if n := cfg.Wrap("/bin/assay"); n != 0 {
		t.Fatalf("second Wrap changed %d servers, want 0", n)
	}
	gh := serversByName(cfg)["github"]
	if gh.Command != "npx" {
		t.Errorf("double wrap corrupted the underlying command: %+v", gh)
	}
}

func TestUnwrapRestoresOriginal(t *testing.T) {
	path := writeFixture(t)
	var before map[string]any
	b, _ := os.ReadFile(path)
	_ = json.Unmarshal(b, &before)

	cfg, _ := Load(path)
	cfg.Wrap("/bin/assay")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	cfg, _ = Load(path)
	if n := cfg.Unwrap(); n != 2 {
		t.Fatalf("Unwrap changed %d, want 2", n)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	var after map[string]any
	b, _ = os.ReadFile(path)
	_ = json.Unmarshal(b, &after)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("unwrap did not restore the original config\nbefore: %v\nafter:  %v", before, after)
	}
}

func TestUnwrapOnCleanConfigIsNoOp(t *testing.T) {
	cfg, _ := Load(writeFixture(t))
	if n := cfg.Unwrap(); n != 0 {
		t.Fatalf("Unwrap on a clean config changed %d, want 0", n)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("Load of a missing file must error")
	}
}

const claudeJSON = `{
  "mcpServers": { "atlassian": { "url": "https://mcp.atlassian.com/v1/mcp" } },
  "numStartups": 42,
  "projects": {
    "/home/dev/proj": {
      "allowedTools": [],
      "mcpServers": {
        "coolify": { "type": "stdio", "command": "npx", "args": ["@masonator/coolify-mcp@latest"], "env": {"COOLIFY_ACCESS_TOKEN": "secret"} }
      }
    }
  }
}`

func writeClaude(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(p, []byte(claudeJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaudeProjectWrapUnwrapRoundTrips(t *testing.T) {
	p := writeClaude(t)
	cfg, err := LoadClaudeProject(p, "/home/dev/proj")
	if err != nil {
		t.Fatal(err)
	}
	if n := cfg.Wrap("/usr/local/bin/assay"); n != 1 {
		t.Fatalf("wrap should change the one stdio server, got %d", n)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	re, _ := LoadClaudeProject(p, "/home/dev/proj")
	if got := serversByName(re)["coolify"]; !got.Wrapped || got.Command != "npx" {
		t.Fatalf("coolify should be wrapped (underlying npx), got %+v", got)
	}
	var raw map[string]any
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &raw)
	if _, ok := raw["mcpServers"].(map[string]any)["atlassian"]; !ok {
		t.Fatal("top-level atlassian server must be preserved")
	}
	if raw["numStartups"] != float64(42) {
		t.Fatalf("unrelated fields must be preserved, got numStartups=%v", raw["numStartups"])
	}
	if n := re.Unwrap(); n != 1 {
		t.Fatalf("unwrap should restore one server, got %d", n)
	}
	if got := serversByName(re)["coolify"]; got.Wrapped {
		t.Fatal("coolify should be unwrapped after Unwrap")
	}
}

func TestClaudeProjectMissingEntryIsNoOp(t *testing.T) {
	cfg, err := LoadClaudeProject(writeClaude(t), "/no/such/project")
	if err != nil {
		t.Fatal(err)
	}
	if n := cfg.Wrap("/usr/local/bin/assay"); n != 0 {
		t.Fatalf("a project with no entry should wrap 0, got %d", n)
	}
}

func serversByName(c *Config) map[string]Server {
	out := map[string]Server{}
	for _, s := range c.Servers() {
		out[s.Name] = s
	}
	return out
}
