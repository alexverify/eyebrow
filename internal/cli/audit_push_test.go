package cli_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// An empty log is a clean no-op (exit 0) that never touches the network,
// distinct from an error.
func TestAuditPushEmptyLog(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "none")
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{
		"audit", "push", "--audit-dir", empty, "--server", "http://127.0.0.1:1", "--token", "tok",
	})
	if code != cli.ExitOK {
		t.Fatalf("an empty log must exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "nothing to send") {
		t.Errorf("empty push should say nothing to send:\n%s", out.String())
	}
}

// A malformed --since date is rejected before any network call.
func TestAuditPushBadSince(t *testing.T) {
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{
		"audit", "push", "--audit-dir", t.TempDir(),
		"--server", "http://127.0.0.1:1", "--token", "tok", "--since", "yesterday",
	})
	if code != cli.ExitUsage {
		t.Errorf("a bad --since date should be a usage error, got %d", code)
	}
}
