package cli_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/agentguard/internal/cli"
)

func TestKeyShowPrintsPublicKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key")
	app, out, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"key", "show", "--key", keyPath}); code != cli.ExitOK {
		t.Fatalf("key show exit = %d, stderr=%s", code, errBuf.String())
	}
	pub := strings.TrimSpace(out.String())
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(raw) != 32 {
		t.Fatalf("key show must print a base64 ed25519 public key, got %q", pub)
	}

	// Stable across invocations (the key persists).
	app, out2, _ := newApp()
	app.Execute(context.Background(), []string{"key", "show", "--key", keyPath})
	if strings.TrimSpace(out2.String()) != pub {
		t.Fatal("key show must print the same persisted key every time")
	}
}

func TestKeyTrustAppendsToRegistry(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "key")
	registry := filepath.Join(tmp, "trusted_keys")

	app, out, _ := newApp()
	app.Execute(context.Background(), []string{"key", "show", "--key", keyPath})
	pub := strings.TrimSpace(out.String())

	app, _, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"key", "trust", "--file", registry, "--name", "alice", pub}); code != cli.ExitOK {
		t.Fatalf("key trust exit = %d, stderr=%s", code, errBuf.String())
	}
	b, err := os.ReadFile(registry)
	if err != nil {
		t.Fatalf("registry not written: %v", err)
	}
	if !strings.Contains(string(b), pub) || !strings.Contains(string(b), "alice") {
		t.Fatalf("registry must contain the key and its label, got %q", b)
	}
}

func TestKeyTrustRejectsMalformed(t *testing.T) {
	registry := filepath.Join(t.TempDir(), "trusted_keys")
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"key", "trust", "--file", registry, "not-a-key"}); code == cli.ExitOK {
		t.Fatal("key trust must reject a malformed key")
	}
}

// TestVerifyCITeamTrustFlow exercises the full team trust story: a signature
// from a key in the committed registry passes verify --ci, one from an
// untrusted key fails.
func TestVerifyCITeamTrustFlow(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // hermetic: no real ~/.agentguard key or registry
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	policyPath := filepath.Join(dir, "agentguard.policy.json")
	mustWriteJSON(t, policyPath, map[string]any{"requireSignature": true})
	registry := filepath.Join(dir, "agentguard.trustedkeys")
	keyA := filepath.Join(t.TempDir(), "keyA")

	ciArgs := []string{"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--policy", policyPath, "--trusted-keys", registry}

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	// Signed by keyA, but keyA not in the registry and no local key: fail.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"sign", "--lockfile", lock, "--key", keyA}); code != cli.ExitOK {
		t.Fatal("sign failed")
	}
	app, out, _ := newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitDrift {
		t.Fatalf("verify --ci with untrusted signer: exit = %d, want %d\n%s", code, cli.ExitDrift, out.String())
	}

	// Trust keyA in the committed registry: pass.
	app, out, _ = newApp()
	app.Execute(ctx, []string{"key", "show", "--key", keyA})
	pubA := strings.TrimSpace(out.String())
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"key", "trust", "--file", registry, "--name", "alice", pubA}); code != cli.ExitOK {
		t.Fatal("key trust failed")
	}
	app, out, errBuf = newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitOK {
		t.Fatalf("verify --ci with trusted signer: exit = %d\nstdout=%s stderr=%s", code, out.String(), errBuf.String())
	}

	// Re-signed by an unknown key while a registry exists: fail again
	// (the registry is authoritative — no implicit self-trust).
	keyB := filepath.Join(t.TempDir(), "keyB")
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"sign", "--lockfile", lock, "--key", keyB}); code != cli.ExitOK {
		t.Fatal("re-sign failed")
	}
	app, _, _ = newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitDrift {
		t.Fatalf("verify --ci with unregistered signer: exit = %d, want %d", code, cli.ExitDrift)
	}
}

// TestVerifyCISelfTrustFallback keeps the single-user flow working: with no
// registry anywhere, a lockfile signed by the local key verifies.
func TestVerifyCISelfTrustFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	policyPath := filepath.Join(dir, "agentguard.policy.json")
	mustWriteJSON(t, policyPath, map[string]any{"requireSignature": true})

	app, _, _ := newApp()
	app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock})

	localKey := filepath.Join(home, ".agentguard", "key")
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"sign", "--lockfile", lock, "--key", localKey}); code != cli.ExitOK {
		t.Fatal("sign failed")
	}

	app, out, errBuf := newApp()
	code := app.Execute(ctx, []string{"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--policy", policyPath, "--trusted-keys", filepath.Join(dir, "agentguard.trustedkeys")})
	if code != cli.ExitOK {
		t.Fatalf("self-signed verify --ci: exit = %d\nstdout=%s stderr=%s", code, out.String(), errBuf.String())
	}
}

func mustWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
