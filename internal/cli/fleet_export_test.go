package cli_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// fleet export writes this machine's snapshot into the shared dir, and fleet
// show aggregates it back — the "git is the backend" round trip.
func TestFleetExportThenShow(t *testing.T) {
	ctx := context.Background()
	proj, _ := fixtureProject(t)
	fleetDir := t.TempDir()

	app, out, errBuf := newApp()
	code := app.Execute(ctx, []string{"fleet", "export", "--dir", fleetDir, "--path", proj, "--owner", "alice"})
	if code != cli.ExitOK {
		t.Fatalf("fleet export exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "alice") {
		t.Errorf("export should confirm the owner:\n%s", out.String())
	}

	app, out, errBuf = newApp()
	code = app.Execute(ctx, []string{"fleet", "show", "--dir", fleetDir, "--policy", filepath.Join(fleetDir, "none.json")})
	if code != cli.ExitOK {
		t.Fatalf("fleet show exit = %d, stderr=%s", code, errBuf.String())
	}
	if out.Len() == 0 {
		t.Error("fleet show should print the aggregated report")
	}
}

// fleet show over an empty dir guides the user rather than erroring.
func TestFleetShowEmptyDir(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "none")
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "show", "--dir", empty})
	if code != cli.ExitOK {
		t.Fatalf("empty fleet show should exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "no fleet snapshots") {
		t.Errorf("empty show should hint at `fleet export`:\n%s", out.String())
	}
}

// An unknown fleet subcommand is a usage error.
func TestFleetUnknownSubcommand(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"fleet", "bogus"}); code != cli.ExitUsage {
		t.Errorf("unknown fleet subcommand should be ExitUsage, got %d", code)
	}
}
