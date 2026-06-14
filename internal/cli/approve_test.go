package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/alexverify/assay/internal/cli"
	"github.com/alexverify/assay/internal/domain/lockfile"
)

func readLockfile(t *testing.T, path string) lockfile.Lockfile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lf lockfile.Lockfile
	if err := json.Unmarshal(b, &lf); err != nil {
		t.Fatal(err)
	}
	return lf
}

func TestApproveAll(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, _ := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"approve", "--all", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("approve --all exit = %d, stderr=%s", code, errBuf.String())
	}

	lf := readLockfile(t, lock)
	if len(lf.Artifacts) == 0 {
		t.Fatal("fixture produced no artifacts")
	}
	for _, e := range lf.Artifacts {
		if e.Approval == nil || e.Approval.Status != "approved" {
			t.Errorf("artifact %s not approved: %+v", e.ID, e.Approval)
		}
	}
}

func TestApproveRequiresIDsOrAll(t *testing.T) {
	dir, lock := fixtureProject(t)
	_ = dir
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"approve", "--lockfile", lock}); code != cli.ExitUsage {
		t.Fatalf("approve without ids or --all must be a usage error, got %d", code)
	}
}

func TestApproveAllRejectsExplicitIDs(t *testing.T) {
	dir, lock := fixtureProject(t)
	app, _, _ := newApp()
	app.Execute(context.Background(), []string{"scan", "--path", dir, "--lockfile", lock})

	app, _, _ = newApp()
	if code := app.Execute(context.Background(), []string{"approve", "--all", "--lockfile", lock, "someid"}); code != cli.ExitUsage {
		t.Fatalf("approve --all with explicit ids must be a usage error, got %d", code)
	}
}
