package cli_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/controlplane"
)

func controlPlane(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(controlplane.NewMemStore(), nil),
		controlplane.StaticAuth{"tok": "acme"},
	))
	t.Cleanup(srv.Close)
	return srv.URL
}

// verify --ci --server consults the control plane for policy and trusted keys,
// then falls back to local when the server has neither — and still gates.
func TestVerifyCIWithServerFallsBackCleanly(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	url := controlPlane(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	app, _, errBuf = newApp()
	code := app.Execute(ctx, []string{
		"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--server", url, "--token", "tok",
	})
	if code != cli.ExitOK {
		t.Fatalf("clean verify against a server-without-policy should pass (0), got %d, stderr=%s", code, errBuf.String())
	}
}

// A bad token makes the control-plane lookups fail; verify warns and falls back
// to local policy/keys rather than failing the run.
func TestVerifyCIServerErrorsAreNonFatal(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	url := controlPlane(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	app, _, errBuf = newApp()
	code := app.Execute(ctx, []string{
		"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--server", url, "--token", "wrong-token",
	})
	if code != cli.ExitOK {
		t.Fatalf("server errors should degrade to local, expected 0, got %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "warning") {
		t.Errorf("a failed control-plane lookup should warn on stderr:\n%s", errBuf.String())
	}
}
