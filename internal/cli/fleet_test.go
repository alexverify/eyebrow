package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// seedFleet writes one snapshot JSON file per owner into a fleet dir.
func seedFleet(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestFleetVerifyCleanPasses(t *testing.T) {
	dir := seedFleet(t, map[string]string{
		"alice.json": `{"owner":"alice","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h","drift":"verified","verdict":"trusted"}]}`,
		"bob.json":   `{"owner":"bob","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h","drift":"verified","verdict":"trusted"}]}`,
	})
	app, _, errBuf := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "verify", "--dir", dir, "--policy", filepath.Join(dir, "none.json")})
	if code != cli.ExitOK {
		t.Fatalf("clean fleet should pass (0), got %d, stderr=%s", code, errBuf.String())
	}
}

func TestFleetVerifyQuarantineFails(t *testing.T) {
	dir := seedFleet(t, map[string]string{
		"alice.json": `{"owner":"alice","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h","drift":"verified","verdict":"trusted"}]}`,
		"bob.json":   `{"owner":"bob","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h2","drift":"verified","verdict":"quarantine"}]}`,
	})
	app, out, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "verify", "--dir", dir, "--policy", filepath.Join(dir, "none.json")})
	if code != cli.ExitDrift {
		t.Fatalf("a quarantined install should fail (1), got %d", code)
	}
	if !strings.Contains(out.String(), "bob") {
		t.Errorf("output should name the offending machine:\n%s", out.String())
	}
}

func TestFleetVerifyBlastRadiusFromPolicy(t *testing.T) {
	dir := seedFleet(t, map[string]string{
		"alice.json": `{"owner":"alice","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h1","drift":"drifted","verdict":"review"}]}`,
		"bob.json":   `{"owner":"bob","artifacts":[{"id":"x","name":"feed","kind":"skill","hash":"h2","drift":"drifted","verdict":"review"}]}`,
	})
	policyPath := filepath.Join(dir, "eyebrow.policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"fleet":{"maxBlastRadius":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "verify", "--dir", dir, "--policy", policyPath})
	if code != cli.ExitDrift {
		t.Fatalf("a drift wider than maxBlastRadius should fail (1), got %d", code)
	}
}

func TestFleetVerifyEmptyDirPasses(t *testing.T) {
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"fleet", "verify", "--dir", filepath.Join(t.TempDir(), "none")})
	if code != cli.ExitOK {
		t.Errorf("no snapshots is nothing to gate; should pass (0), got %d", code)
	}
}
