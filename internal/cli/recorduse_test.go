package cli_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/domain/audit"
)

func TestRecordUseAppendsActivation(t *testing.T) {
	dir := t.TempDir()
	app, _, errBuf := newApp()
	code := app.Execute(context.Background(), []string{
		"record-use", "--audit-dir", dir, "--kind", "skill", "--name", "pdf-skill",
	})
	if code != cli.ExitOK {
		t.Fatalf("record-use exit = %d, stderr=%s", code, errBuf.String())
	}

	events, err := auditlog.Read(dir, auditlog.Filter{})
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if e.Kind != audit.KindActivation {
		t.Errorf("Kind = %q, want activation", e.Kind)
	}
	if e.Server != "pdf-skill" {
		t.Errorf("Server = %q, want the artifact name (the usage join key)", e.Server)
	}
	if e.Tool != "skill" {
		t.Errorf("Tool = %q, want the artifact kind", e.Tool)
	}
	if e.ArgsDigest != "" {
		t.Errorf("activation must never carry argument data, got argsDigest=%q", e.ArgsDigest)
	}
}

func TestRecordUseNeverFailsHost(t *testing.T) {
	// A hook shells out to record-use on every skill/subagent invocation; a bad
	// or missing arg must never break the host tool. It degrades to exit 0 and
	// simply records nothing — the shim's degrade discipline.
	dir := t.TempDir()
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"record-use", "--audit-dir", dir, "--kind", "skill"})
	if code != cli.ExitOK {
		t.Fatalf("missing --name must still exit 0, got %d", code)
	}
	events, err := auditlog.Read(dir, auditlog.Filter{})
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("nothing should be recorded without a name, got %d events", len(events))
	}
}

func TestRecordUseReadsHookJSONFromStdin(t *testing.T) {
	// Claude Code PreToolUse hooks pipe a JSON event on stdin. record-use accepts
	// --stdin and extracts the artifact name from tool_input, so the hook needs
	// no shell plumbing to pull the field out.
	dir := t.TempDir()
	app, _, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"tool_name":"Skill","tool_input":{"command":"pdf-skill"}}`)
	code := app.Execute(context.Background(), []string{"record-use", "--audit-dir", dir, "--kind", "skill", "--stdin"})
	if code != cli.ExitOK {
		t.Fatalf("record-use --stdin exit = %d, stderr=%s", code, errBuf.String())
	}
	events, err := auditlog.Read(dir, auditlog.Filter{})
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(events) != 1 || events[0].Server != "pdf-skill" {
		t.Fatalf("expected one activation for pdf-skill, got %+v", events)
	}
}
