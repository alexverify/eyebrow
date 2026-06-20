package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

func mcpFixtureProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := `{
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readConfig(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := mcpFixtureProject(t)
	before := readConfig(t, dir)

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"wrap", "--path", dir}); code != cli.ExitOK {
		t.Fatalf("wrap exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "wrapped 1") {
		t.Errorf("wrap output = %q", out.String())
	}

	entry := readConfig(t, dir)["mcpServers"].(map[string]any)["github"].(map[string]any)
	args, _ := entry["args"].([]any)
	if len(args) == 0 || args[0] != "mcp-shim" {
		t.Fatalf("config not rewritten to the shim: %v", entry)
	}

	// Idempotent: wrapping again changes nothing.
	app, out, _ = newApp()
	if code := app.Execute(ctx, []string{"wrap", "--path", dir}); code != cli.ExitOK {
		t.Fatal("second wrap must succeed")
	}
	if !strings.Contains(out.String(), "wrapped 0") {
		t.Errorf("second wrap output = %q", out.String())
	}

	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"unwrap", "--path", dir}); code != cli.ExitOK {
		t.Fatal("unwrap failed")
	}
	after := readConfig(t, dir)
	if string(mustJSON(t, before)) != string(mustJSON(t, after)) {
		t.Errorf("unwrap did not restore the original:\nbefore %v\nafter  %v", before, after)
	}
}

func TestWrapStatusListsServers(t *testing.T) {
	ctx := context.Background()
	dir := mcpFixtureProject(t)

	app, out, _ := newApp()
	app.Execute(ctx, []string{"wrap", "--status", "--path", dir})
	if !strings.Contains(out.String(), "github") || !strings.Contains(out.String(), "not wrapped") {
		t.Errorf("status before wrap = %q", out.String())
	}

	app, _, _ = newApp()
	app.Execute(ctx, []string{"wrap", "--path", dir})
	app, out, _ = newApp()
	app.Execute(ctx, []string{"wrap", "--status", "--path", dir})
	if !strings.Contains(out.String(), "wrapped") || !strings.Contains(out.String(), "npx") {
		t.Errorf("status after wrap = %q (must show underlying command)", out.String())
	}
}

// TestWrapCausesNoDrift is the regression that keeps scan and wrap compatible:
// wrapping must not change what verify sees, or every wrap would read as a
// rug pull.
func TestWrapCausesNoDrift(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t) // local stdio server, no network needed

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"wrap", "--path", dir}); code != cli.ExitOK {
		t.Fatal("wrap failed")
	}

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"verify", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("verify after wrap: exit = %d (wrap must not read as drift)\nstdout=%s stderr=%s",
			code, out.String(), errBuf.String())
	}
}

func TestWrapGlobalScope(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	cfg := `{
  "mcpServers": {"global-tool": {"command": "node", "args": ["g.js"]}},
  "projects": {"/x": {"foo": 1}}
}`
	globalPath := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(globalPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"wrap", "--global"}); code != cli.ExitOK {
		t.Fatalf("wrap --global exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "wrapped 1") {
		t.Errorf("wrap --global output = %q", out.String())
	}
	raw := readConfigAt(t, globalPath)
	entry := raw["mcpServers"].(map[string]any)["global-tool"].(map[string]any)
	if args, _ := entry["args"].([]any); len(args) == 0 || args[0] != "mcp-shim" {
		t.Fatalf("global config not rewritten: %v", entry)
	}
	// Unrelated top-level keys must survive.
	if _, ok := raw["projects"]; !ok {
		t.Error("wrap --global must preserve other top-level keys")
	}

	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"unwrap", "--global"}); code != cli.ExitOK {
		t.Fatal("unwrap --global failed")
	}
	entry = readConfigAt(t, globalPath)["mcpServers"].(map[string]any)["global-tool"].(map[string]any)
	if entry["command"] != "node" {
		t.Errorf("unwrap --global did not restore: %v", entry)
	}
}

func readConfigAt(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWrapUnsupportedTool(t *testing.T) {
	app, _, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"wrap", "--tool", "cursor", "--path", t.TempDir()}); code != cli.ExitUsage {
		t.Fatalf("unsupported tool: exit = %d, want usage error (stderr=%s)", code, errBuf.String())
	}
}

func TestWrapWithoutConfig(t *testing.T) {
	// Isolate HOME so there is no ~/.claude.json either: with no config source
	// anywhere, wrap reports an error.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"wrap", "--path", t.TempDir()}); code != cli.ExitError {
		t.Fatalf("wrap with no config anywhere: exit = %d, want %d", code, cli.ExitError)
	}
}

// TestWrapPerProjectStore covers a server registered in Claude Code's per-project
// store inside ~/.claude.json (the "local" scope), with no committable .mcp.json.
func TestWrapPerProjectStore(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	proj := t.TempDir() // no .mcp.json here
	// The per-project key is the absolute project path; marshal via encoding/json
	// so a Windows path's backslashes are escaped (string concatenation would
	// produce invalid JSON like "C:\Users").
	abs, err := filepath.Abs(proj)
	if err != nil {
		t.Fatal(err)
	}
	claude := map[string]any{
		"mcpServers": map[string]any{"atlassian": map[string]any{"url": "https://mcp.atlassian.com/v1/mcp"}},
		"projects": map[string]any{
			abs: map[string]any{
				"mcpServers": map[string]any{
					"coolify": map[string]any{
						"type": "stdio", "command": "npx", "args": []any{"@masonator/coolify-mcp@latest"},
					},
				},
			},
		},
	}
	b, err := json.Marshal(claude)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}

	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"wrap", "--path", proj}); code != cli.ExitOK {
		t.Fatalf("wrap = %d", code)
	}
	if !strings.Contains(out.String(), "wrapped 1 server") {
		t.Fatalf("expected to wrap the per-project coolify server, got %q", out.String())
	}

	app, out, _ = newApp()
	app.Execute(ctx, []string{"wrap", "--status", "--path", proj})
	if !strings.Contains(out.String(), "coolify") || !strings.Contains(out.String(), "wrapped") {
		t.Fatalf("status should list coolify as wrapped, got %q", out.String())
	}

	app, out, _ = newApp()
	if code := app.Execute(ctx, []string{"unwrap", "--path", proj}); code != cli.ExitOK {
		t.Fatalf("unwrap = %d", code)
	}
	if !strings.Contains(out.String(), "unwrapped 1 server") {
		t.Fatalf("expected to unwrap coolify, got %q", out.String())
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
