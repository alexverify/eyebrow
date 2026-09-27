package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// oneJSONDoc decodes exactly one JSON document from b and fails if anything
// but whitespace follows it (a posture line, a policy line).
func oneJSONDoc(t *testing.T, b []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, b)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout has content after the JSON document:\n%s", b)
	}
}

type verifyJSON struct {
	Changes []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"changes"`
}

func TestToolScanVerifyRoundTripIsCleanJSON(t *testing.T) {
	project, lock := openclawHome(t)
	ctx := context.Background()
	args := []string{"--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"}

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, append([]string{"scan"}, args...)); code != cli.ExitOK {
		t.Fatalf("scan exit %d: %s", code, errBuf)
	}
	var lf struct {
		Artifacts []struct {
			ID       string `json:"id"`
			Tool     string `json:"tool"`
			Type     string `json:"type"`
			Name     string `json:"name"`
			Findings []struct {
				RuleID   string `json:"ruleId"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"artifacts"`
	}
	oneJSONDoc(t, out.Bytes(), &lf)
	if len(lf.Artifacts) != 1 || lf.Artifacts[0].ID == "" || lf.Artifacts[0].Type != "skill" {
		t.Fatalf("unexpected scan JSON: %+v", lf)
	}

	app, out, errBuf = newApp()
	if code := app.Execute(ctx, append([]string{"verify"}, args...)); code != cli.ExitOK {
		t.Fatalf("verify exit %d: %s\n%s", code, errBuf, out)
	}
	var clean verifyJSON
	oneJSONDoc(t, out.Bytes(), &clean)
	if len(clean.Changes) != 0 {
		t.Fatalf("round trip must be clean, got %+v", clean.Changes)
	}
}

func TestToolVerifyReportsDriftAsJSON(t *testing.T) {
	project, lock := openclawHome(t)
	ctx := context.Background()
	args := []string{"--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"}
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, append([]string{"scan"}, args...)); code != cli.ExitOK {
		t.Fatalf("scan exit %d: %s", code, errBuf)
	}
	home, _ := os.UserHomeDir()
	skillMd := filepath.Join(home, ".openclaw", "skills", "demo", "SKILL.md")
	if err := os.WriteFile(skillMd, []byte("---\ndescription: demo\n---\nchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, append([]string{"verify"}, args...)); code != cli.ExitDrift {
		t.Fatalf("verify exit %d, want %d: %s", code, cli.ExitDrift, errBuf)
	}
	var d verifyJSON
	oneJSONDoc(t, out.Bytes(), &d)
	if len(d.Changes) != 1 || d.Changes[0].Kind != "content_changed" || d.Changes[0].Name != "demo" || d.Changes[0].ID == "" {
		t.Fatalf("want one content_changed for demo, got %+v", d.Changes)
	}
}

// A lockfile from a full scan holds every tool. verify --tool compares only
// that tool's entries, so the others do not read as removed.
func TestToolVerifyIgnoresOtherToolsInLockfile(t *testing.T) {
	project, lock := openclawHome(t)
	ctx := context.Background()
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", project, "--global", "--lockfile", lock, "--json"}); code != cli.ExitOK {
		t.Fatalf("full scan exit %d: %s", code, errBuf)
	}
	app, out, errBuf := newApp()
	code := app.Execute(ctx, []string{"verify", "--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"})
	if code != cli.ExitOK {
		t.Fatalf("verify --tool exit %d, want %d: %s\n%s", code, cli.ExitOK, errBuf, out)
	}
	var d verifyJSON
	oneJSONDoc(t, out.Bytes(), &d)
	if len(d.Changes) != 0 {
		t.Fatalf("verify --tool must report no changes, got %+v", d.Changes)
	}
}

// scan --tool on a lockfile holding other tools would drop them; it refuses
// and leaves the lockfile as it was.
func TestToolScanRefusesToShrinkSharedLockfile(t *testing.T) {
	project, lock := openclawHome(t)
	ctx := context.Background()
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", project, "--global", "--lockfile", lock, "--json"}); code != cli.ExitOK {
		t.Fatalf("full scan exit %d: %s", code, errBuf)
	}
	before, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	app, _, errBuf = newApp()
	code := app.Execute(ctx, []string{"scan", "--path", project, "--global", "--tool", "openclaw", "--lockfile", lock, "--json"})
	if code != cli.ExitUsage {
		t.Fatalf("scan --tool exit %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(errBuf.String(), "holds other tools' artifacts; use a separate --lockfile with --tool") {
		t.Errorf("stderr must explain the refusal: %q", errBuf)
	}
	after, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("scan --tool rewrote the shared lockfile")
	}
}
