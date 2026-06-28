package cli_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// dashboard binds a loopback listener, prints its URL and write token, and shuts
// down cleanly when its context is cancelled. This also exercises the keyring
// and approval-verifier wiring the dashboard builds at startup.
func TestDashboardStartsAndShutsDownCleanly(t *testing.T) {
	setHome(t, t.TempDir()) // keep key/keyring lookups off the real home
	dir, _ := fixtureProject(t)

	ctx, cancel := context.WithCancel(context.Background())
	app, out, _ := newApp()
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(ctx, []string{"dashboard", "--addr", "127.0.0.1:0", "--path", dir})
	}()
	cancel()
	if code := <-done; code != cli.ExitOK {
		t.Fatalf("dashboard should exit 0 on graceful shutdown, got %d", code)
	}
	if !strings.Contains(out.String(), "eyebrow dashboard on http://") {
		t.Errorf("dashboard should announce its loopback URL:\n%s", out.String())
	}
}
