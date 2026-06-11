package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/agentguard/internal/cli"
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

func TestWrapUnsupportedTool(t *testing.T) {
	app, _, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"wrap", "--tool", "cursor", "--path", t.TempDir()}); code != cli.ExitUsage {
		t.Fatalf("unsupported tool: exit = %d, want usage error (stderr=%s)", code, errBuf.String())
	}
}

func TestWrapWithoutConfig(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"wrap", "--path", t.TempDir()}); code != cli.ExitError {
		t.Fatalf("wrap with no .mcp.json: exit = %d, want %d", code, cli.ExitError)
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
