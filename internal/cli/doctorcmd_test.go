package cli_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

func TestDoctorReportsToolsAndLockfile(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	// Before scan: no lockfile is a warning, but doctor is a report, not a gate,
	// so it still exits 0.
	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	s := out.String()
	for _, want := range []string{"doctor", "tools", "lockfile"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n%s", want, s)
		}
	}
	if !strings.Contains(s, "warn") {
		t.Errorf("a missing lockfile should warn:\n%s", s)
	}

	// The fixture project has a discoverable MCP server, so the tools check is ok.
	if !strings.Contains(s, "discovered") {
		t.Errorf("expected a discovered-artifacts detail:\n%s", s)
	}

	// After scan the lockfile exists, so its check is no longer a warning.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}
	app, out, _ = newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "present") {
		t.Errorf("expected the lockfile check to report it present:\n%s", out.String())
	}
}

func TestDoctorReportsSandbox(t *testing.T) {
	dir, lock := fixtureProject(t)
	app, out, _ := newApp()
	app.Execute(context.Background(), []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "sandbox") {
		t.Errorf("doctor should include a sandbox check:\n%s", out.String())
	}
}
