package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// TestSignedApprovalGate: requireSignedApproval passes only when approvals are
// signed by a trusted key, and a hand-edited (unsigned) approval is rejected.
func TestSignedApprovalGate(t *testing.T) {
	setHome(t, t.TempDir()) // hermetic key + trusted-keys location
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	policyPath := filepath.Join(dir, "eyebrow.policy.json")
	mustWriteJSON(t, policyPath, map[string]any{"requireSignedApproval": true})
	registry := filepath.Join(dir, "eyebrow.trustedkeys")
	ciArgs := []string{"verify", "--ci", "--path", dir, "--lockfile", lock,
		"--policy", policyPath, "--trusted-keys", registry}

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan: %d %s", code, errBuf.String())
	}

	// Trust our own key (so the registry is authoritative and self-trust is off).
	app, out, _ := newApp()
	app.Execute(ctx, []string{"key", "show"})
	pub := strings.TrimSpace(out.String())
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"key", "trust", "--file", registry, pub}); code != cli.ExitOK {
		t.Fatal("key trust failed")
	}

	// Unsigned approval → gate fails.
	app, _, _ = newApp()
	app.Execute(ctx, []string{"approve", "--all", "--lockfile", lock})
	app, out, _ = newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitDrift {
		t.Fatalf("unsigned approval must fail the gate, exit=%d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not validly signed") {
		t.Errorf("expected an unsigned-approval violation:\n%s", out.String())
	}

	// Signed approval → gate passes.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"approve", "--all", "--sign", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("approve --sign failed")
	}
	app, out, errBuf = newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitOK {
		t.Fatalf("signed approval must pass, exit=%d\nstdout=%s stderr=%s", code, out.String(), errBuf.String())
	}

	// Tamper: flip the approval signature in the lockfile → gate fails again.
	b, _ := os.ReadFile(lock)
	var lf lockfile.Lockfile
	_ = json.Unmarshal(b, &lf)
	if len(lf.Artifacts) == 0 || lf.Artifacts[0].Approval == nil || lf.Artifacts[0].Approval.Sig == "" {
		t.Fatal("expected a signed approval in the lockfile")
	}
	lf.Artifacts[0].Approval.By = "mallory" // signature commits to id+hash, not By…
	// …so flip the actual signature bytes to prove forgery is caught:
	lf.Artifacts[0].Approval.Sig = "ed25519:AAAA"
	nb, _ := json.Marshal(lf)
	_ = os.WriteFile(lock, nb, 0o644)

	app, out, _ = newApp()
	if code := app.Execute(ctx, ciArgs); code != cli.ExitDrift {
		t.Fatalf("a forged approval signature must fail, exit=%d\n%s", code, out.String())
	}
}
