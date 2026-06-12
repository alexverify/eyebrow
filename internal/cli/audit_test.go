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

func seedAuditDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lines := []string{
		`{"ts":"2026-06-11T10:00:00Z","session":"s1","server":"github","kind":"tool_call","tool":"create_issue","status":"ok","durationMs":120}`,
		`{"ts":"2026-06-11T10:00:02Z","session":"s1","server":"github","kind":"tool_call","tool":"delete_repo","status":"denied","detail":"denied by github denyTools delete_*"}`,
		`{"ts":"2026-06-12T09:00:00Z","session":"s2","server":"db","kind":"egress","host":"evil.example","status":"denied"}`,
		`{"ts":"2026-06-12T09:00:01Z","session":"s2","server":"db","kind":"egress","host":"api.ok.example","status":"ok","redactions":1}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "2026-06-12.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAuditSummary(t *testing.T) {
	dir := seedAuditDir(t)
	app, out, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"audit", "--audit-dir", dir}); code != cli.ExitOK {
		t.Fatalf("audit exit = %d, stderr=%s", code, errBuf.String())
	}
	s := out.String()
	for _, want := range []string{"github", "db", "denied", "2"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}

func TestAuditDeniedFilter(t *testing.T) {
	dir := seedAuditDir(t)
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"audit", "--audit-dir", dir, "--status", "denied", "--list"})
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	s := out.String()
	if !strings.Contains(s, "delete_repo") || !strings.Contains(s, "evil.example") {
		t.Errorf("denied list missing entries:\n%s", s)
	}
	if strings.Contains(s, "create_issue") {
		t.Errorf("denied filter leaked an ok event:\n%s", s)
	}
}

func TestAuditJSON(t *testing.T) {
	dir := seedAuditDir(t)
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"audit", "--audit-dir", dir, "--list", "--json"})
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var events []map[string]any
	if err := json.Unmarshal(out.Bytes(), &events); err != nil {
		t.Fatalf("--json must emit a JSON array: %v\n%s", err, out.String())
	}
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4", len(events))
	}
}

func TestAuditServerFilter(t *testing.T) {
	dir := seedAuditDir(t)
	app, out, _ := newApp()
	app.Execute(context.Background(), []string{"audit", "--audit-dir", dir, "--server", "db", "--list"})
	s := out.String()
	if strings.Contains(s, "github") {
		t.Errorf("server filter leaked github:\n%s", s)
	}
}

func TestAuditEmptyLog(t *testing.T) {
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"audit", "--audit-dir", filepath.Join(t.TempDir(), "none")})
	if code != cli.ExitOK {
		t.Fatalf("empty log must exit 0, got %d", code)
	}
	if !strings.Contains(strings.ToLower(out.String()), "no audit") {
		t.Errorf("empty log should say so:\n%s", out.String())
	}
}
