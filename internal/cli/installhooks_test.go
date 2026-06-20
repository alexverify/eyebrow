package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

func TestInstallHooksRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	app, out, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"install-hooks", "--settings", path}); code != cli.ExitOK {
		t.Fatalf("install exit = %d, stderr=%s", code, errBuf.String())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings not written: %v", err)
	}
	if !strings.Contains(string(b), "record-use") {
		t.Errorf("settings missing the record-use hook:\n%s", b)
	}

	// status reports the installed hooks
	app, out, _ = newApp()
	app.Execute(context.Background(), []string{"install-hooks", "--settings", path, "--status"})
	if !strings.Contains(out.String(), "record-use") {
		t.Errorf("status should list the hook:\n%s", out.String())
	}

	// uninstall removes them
	app, out, _ = newApp()
	app.Execute(context.Background(), []string{"install-hooks", "--settings", path, "--uninstall"})
	app2, out2, _ := newApp()
	app2.Execute(context.Background(), []string{"install-hooks", "--settings", path, "--status"})
	if strings.Contains(out2.String(), "record-use") {
		t.Errorf("hooks should be gone after uninstall:\n%s", out2.String())
	}
}

func TestInstallHooksRejectsUnknownTool(t *testing.T) {
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"install-hooks", "--tool", "vim"})
	if code != cli.ExitUsage {
		t.Errorf("unknown tool should be a usage error, got %d", code)
	}
}
