package cli_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/cli"
)

// freePort binds :0 to learn an unused loopback address, then releases it so the
// dashboard can take it. Passing a fixed addr lets the test reach the server
// without racing to read its announced URL out of the shared output buffer.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// get issues a GET and returns the status code, failing the test on a transport
// error. Read endpoints are open (only mutations require the write token).
func get(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

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

// Driving real GETs against a running dashboard exercises the data-source
// closures runDashboard wires (inventory, drift, history, fleet, alerts) — the
// glue between the CLI and the dashboard server, not covered by startup alone.
func TestDashboardServesReadEndpoints(t *testing.T) {
	setHome(t, t.TempDir())
	dir, _ := fixtureProject(t)
	tmp := t.TempDir()
	addr := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app, _, _ := newApp()
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(ctx, []string{
			"dashboard", "--addr", addr, "--path", dir,
			"--policy", filepath.Join(tmp, "policy.json"),
			"--reputation", filepath.Join(tmp, "rep.json"),
			"--fleet-dir", filepath.Join(tmp, "fleet"),
		})
	}()

	base := "http://" + addr
	// Wait for the listener to come up (the goroutine binds asynchronously).
	var up bool
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
			c.Close()
			up = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatal("dashboard never started listening")
	}

	for _, path := range []string{"/api/scan", "/api/history", "/api/fleet", "/api/alerts", "/api/inventory"} {
		if code := get(t, base+path); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
	}

	cancel()
	if code := <-done; code != cli.ExitOK {
		t.Errorf("dashboard should exit 0 on graceful shutdown, got %d", code)
	}
}
