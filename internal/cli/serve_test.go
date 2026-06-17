package cli_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/assay/internal/cli"
	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
)

func TestFleetPushThenShowRemote(t *testing.T) {
	// Stand up a real control-plane server, push this fixture project's snapshot
	// to it, then read the aggregated fleet back through the same CLI.
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(controlplane.NewMemStore(), nil),
		controlplane.StaticAuth{"tok": "acme"},
	))
	t.Cleanup(srv.Close)

	dir, lock := fixtureProject(t)
	ctx := context.Background()

	push, out, errBuf := newApp()
	code := push.Execute(ctx, []string{
		"fleet", "push", "--path", dir, "--lockfile", lock,
		"--owner", "alice", "--server", srv.URL, "--token", "tok",
	})
	if code != cli.ExitOK {
		t.Fatalf("push exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "pushed fleet snapshot") {
		t.Errorf("push should confirm: %s", out.String())
	}

	show, sout, _ := newApp()
	code = show.Execute(ctx, []string{"fleet", "--server", srv.URL, "--token", "tok"})
	if code != cli.ExitOK {
		t.Fatalf("remote show exit = %d", code)
	}
	if !strings.Contains(sout.String(), "1 machines") {
		t.Errorf("remote fleet should report alice's machine:\n%s", sout.String())
	}
}

func TestFleetPushRequiresServer(t *testing.T) {
	dir, lock := fixtureProject(t)
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "push", "--path", dir, "--lockfile", lock})
	if code != cli.ExitUsage {
		t.Errorf("push without a server should be a usage error, got %d", code)
	}
}

func TestServeRequiresTokens(t *testing.T) {
	app, _, errBuf := newApp()
	code := app.Execute(context.Background(), []string{"serve", "--addr", "127.0.0.1:0"})
	if code != cli.ExitUsage {
		t.Fatalf("serve without --tokens should be a usage error, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "tokens") {
		t.Errorf("error should mention tokens: %s", errBuf.String())
	}
}

func TestFleetVerifyRemoteGate(t *testing.T) {
	// Two machines pushed a drift of the same artifact; the org policy caps the
	// blast radius at 1. `fleet verify --server` gates the fleet on the server
	// (no local snapshot dir) and must fail.
	store := controlplane.NewMemStore()
	for _, h := range []struct{ owner, hash string }{{"alice", "h1"}, {"bob", "h2"}} {
		store.PutSnapshot("acme", fleet.Snapshot{Owner: h.owner, Artifacts: []fleet.Artifact{
			{ID: "x", Name: "feed", Kind: "skill", Hash: h.hash, Drift: "drifted", Verdict: "review"},
		}})
	}
	cfg := controlplane.NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{Fleet: policy.FleetPolicy{MaxBlastRadius: 1}})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(store, cfg), controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)

	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "verify", "--server", srv.URL, "--token", "tok"})
	if code != cli.ExitDrift {
		t.Fatalf("remote gate should fail (1), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "blast radius") {
		t.Errorf("should report the breach:\n%s", out.String())
	}
}

func TestFleetVerifyRemoteGateClean(t *testing.T) {
	store := controlplane.NewMemStore()
	store.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "x", Name: "feed", Hash: "h", Drift: "verified", Verdict: "trusted"}}})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(store, controlplane.NewMemConfig()), controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)

	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"fleet", "verify", "--server", srv.URL, "--token", "tok"}); code != cli.ExitOK {
		t.Errorf("a clean remote fleet should pass (0), got %d", code)
	}
}

func TestServeRejectsEmptyTokensFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"serve", "--addr", "127.0.0.1:0", "--tokens", path})
	if code != cli.ExitUsage {
		t.Errorf("an empty tokens file should be rejected, got %d", code)
	}
}
