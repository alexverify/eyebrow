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

// openclawHome builds a project with a Claude Code MCP server (fixtureProject)
// and a fake home with one OpenClaw skill, so a --tool filter has something
// to leave out.
func openclawHome(t *testing.T) (project, lock string) {
	t.Helper()
	project, lock = fixtureProject(t)
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("OPENCLAW_STATE_DIR", "")
	skill := filepath.Join(home, ".openclaw", "skills", "demo")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\ndescription: demo\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return project, lock
}

func TestScanToolKeepsOnlyThatTool(t *testing.T) {
	project, lock := openclawHome(t)
	app, out, errBuf := newApp()
	code := app.Execute(context.Background(), []string{"scan", "--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"})
	if code != cli.ExitOK {
		t.Fatalf("scan exit %d, stderr %s", code, errBuf)
	}
	var lf struct {
		Artifacts []struct {
			Tool string `json:"tool"`
			Name string `json:"name"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(out.Bytes(), &lf); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	if len(lf.Artifacts) != 1 || lf.Artifacts[0].Tool != "openclaw" || lf.Artifacts[0].Name != "demo" {
		t.Fatalf("want only the openclaw skill, got %+v", lf.Artifacts)
	}
}

func TestToolFlagRejectsUnknownTool(t *testing.T) {
	project, lock := openclawHome(t)
	for _, cmd := range []string{"scan", "verify"} {
		app, _, errBuf := newApp()
		code := app.Execute(context.Background(), []string{cmd, "--path", project, "--tool", "nope", "--lockfile", lock})
		if code != cli.ExitUsage {
			t.Errorf("%s --tool nope: exit %d, want %d", cmd, code, cli.ExitUsage)
		}
		if !strings.Contains(errBuf.String(), `unknown tool "nope"`) {
			t.Errorf("%s: stderr must name the tool: %s", cmd, errBuf)
		}
	}
}

func TestToolResetsBetweenInvocations(t *testing.T) {
	project, lock := openclawHome(t)
	lock2 := filepath.Join(t.TempDir(), "lock2.json")

	app, out, _ := newApp()

	// First invocation: scan with --tool openclaw
	code := app.Execute(context.Background(), []string{"scan", "--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"})
	if code != cli.ExitOK {
		t.Fatalf("first scan exit %d", code)
	}
	var lf1 struct {
		Artifacts []struct {
			Tool string `json:"tool"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(out.Bytes(), &lf1); err != nil {
		t.Fatalf("first scan stdout not JSON: %v", err)
	}
	if len(lf1.Artifacts) != 1 || lf1.Artifacts[0].Tool != "openclaw" {
		t.Fatalf("first scan: want only openclaw, got %+v", lf1.Artifacts)
	}

	// Reset output buffer for second invocation
	out.Reset()

	// Second invocation: scan without --tool on same App
	code = app.Execute(context.Background(), []string{"scan", "--path", project, "--global", "--lockfile", lock2, "--json"})
	if code != cli.ExitOK {
		t.Fatalf("second scan exit %d", code)
	}
	var lf2 struct {
		Artifacts []struct {
			Tool string `json:"tool"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(out.Bytes(), &lf2); err != nil {
		t.Fatalf("second scan stdout not JSON: %v", err)
	}
	// Second scan should include non-openclaw tools (e.g., claude-code from fixture)
	hasNonOpenClaw := false
	for _, a := range lf2.Artifacts {
		if a.Tool != "openclaw" {
			hasNonOpenClaw = true
			break
		}
	}
	if !hasNonOpenClaw {
		t.Fatalf("second scan: want non-openclaw tools, got only %+v", lf2.Artifacts)
	}
}
