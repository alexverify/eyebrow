package cli_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/controlplane"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

func TestServeRejectsMissingTokensFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"serve", "--addr", "127.0.0.1:0", "--tokens", missing}); code != cli.ExitUsage {
		t.Errorf("a missing tokens file should be a usage error, got %d", code)
	}
}

func TestServeRejectsMalformedTokensFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"serve", "--addr", "127.0.0.1:0", "--tokens", path}); code != cli.ExitUsage {
		t.Errorf("a malformed tokens file should be a usage error, got %d", code)
	}
}

// serve binds, announces, and shuts down cleanly when its context is cancelled
// (the path cmd/eyebrow uses on SIGINT) — exiting 0, not as an error.
func TestServeStartsAndShutsDownCleanly(t *testing.T) {
	tokens := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(tokens, []byte(`{"tok":"acme"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	app, _, _ := newApp()
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(ctx, []string{
			"serve", "--addr", "127.0.0.1:0", "--tokens", tokens, "--store", t.TempDir(),
		})
	}()
	// Cancelling triggers the server's graceful Shutdown; ListenAndServe then
	// returns http.ErrServerClosed, which runServe maps to a clean exit.
	cancel()
	if code := <-done; code != cli.ExitOK {
		t.Errorf("serve should exit 0 on graceful shutdown, got %d", code)
	}
}

func TestAlertsRequiresServer(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"alerts"}); code != cli.ExitUsage {
		t.Errorf("alerts without a server should be a usage error, got %d", code)
	}
}

// When the control plane serves a policy and trusted keys, verify --ci pulls
// and enforces them (the org-config path, not the local fallback).
func TestVerifyCIUsesServerPolicy(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	cfg := controlplane.NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{}) // present but permissive
	cfg.SetTrustedKeys("acme", nil)
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(controlplane.NewMemStore(), cfg),
		controlplane.StaticAuth{"tok": "acme"},
	))
	t.Cleanup(srv.Close)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	app, _, errBuf = newApp()
	code := app.Execute(ctx, []string{
		"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--server", srv.URL, "--token", "tok",
	})
	if code != cli.ExitOK {
		t.Fatalf("clean verify under a permissive server policy should pass (0), got %d, stderr=%s", code, errBuf.String())
	}
}
