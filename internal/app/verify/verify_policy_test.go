package verify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/apptest"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/app/verify"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

type fakeLockVerifier struct{ err error }

func (f fakeLockVerifier) VerifyLockfile(lockfile.Lockfile) error { return f.err }

type fakeApprovalVerifier struct{ err error }

func (f fakeApprovalVerifier) VerifyApproval(lockfile.Entry) error { return f.err }

// serviceWith builds a verify service over one store, optionally wired with a
// lockfile verifier and an approval verifier (pass nil to omit either).
func serviceWith(t *testing.T, store *apptest.LockStore, lv ports.LockfileVerifier, av ports.ApprovalVerifier) *verify.Service {
	t.Helper()
	builder := scan.New(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("srv")}},
		Resolver:   apptest.Resolver{},
		Hasher:     apptest.Hasher{HashValue: "sha256-a"},
		Analyzer:   apptest.Analyzer{},
		Lock:       store,
		Reporter:   apptest.Reporter{},
		Clock:      apptest.FixedClock{T: time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)},
		Generator:  "eyebrow/test",
	})
	return verify.New(verify.Deps{
		Builder: builder, Lock: store, Reporter: apptest.Reporter{},
		Verifier: lv, ApprovalVerifier: av,
	})
}

func hasViolation(vs []policy.Violation, kind, detailSubstr string) bool {
	for _, v := range vs {
		if v.Kind == kind && strings.Contains(v.Detail, detailSubstr) {
			return true
		}
	}
	return false
}

func TestVerifyRequireSignatureWithoutVerifier(t *testing.T) {
	store := apptest.NewLockStore()
	seed(t, store, "sha256-a", nil)
	svc := serviceWith(t, store, nil, nil) // no lockfile verifier available

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json", CI: true,
		Policy: policy.Policy{RequireSignature: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("RequireSignature with no verifier must fail")
	}
	if !hasViolation(res.Policy.Violations, "signature", "no signing key") {
		t.Errorf("expected a 'no signing key' signature violation, got %+v", res.Policy.Violations)
	}
}

func TestVerifyRequireSignatureVerifierRejects(t *testing.T) {
	store := apptest.NewLockStore()
	seed(t, store, "sha256-a", nil)
	svc := serviceWith(t, store, fakeLockVerifier{err: errors.New("bad signature")}, nil)

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json", CI: true,
		Policy: policy.Policy{RequireSignature: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !hasViolation(res.Policy.Violations, "signature", "bad signature") {
		t.Errorf("expected a signature violation carrying the verifier error, got %+v", res.Policy.Violations)
	}
}

func TestVerifyRequireSignatureVerifierAccepts(t *testing.T) {
	store := apptest.NewLockStore()
	seed(t, store, "sha256-a", nil)
	svc := serviceWith(t, store, fakeLockVerifier{err: nil}, nil)

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json", CI: true,
		Policy: policy.Policy{RequireSignature: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("a valid signature should pass, got violations %+v", res.Policy.Violations)
	}
}

func TestVerifyRequireSignedApprovalWithoutVerifier(t *testing.T) {
	store := apptest.NewLockStore()
	seed(t, store, "sha256-a", nil)
	svc := serviceWith(t, store, nil, nil) // no approval verifier available

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json", CI: true,
		Policy: policy.Policy{RequireSignedApproval: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !hasViolation(res.Policy.Violations, "unsigned_approval", "no signing key") {
		t.Errorf("expected an unsigned_approval violation when no verifier is wired, got %+v", res.Policy.Violations)
	}
}

func TestVerifyRequireSignedApprovalForgedSignature(t *testing.T) {
	store := apptest.NewLockStore()
	// A locked artifact marked approved, but its approval signature is invalid.
	a := mcp("srv")
	a.ContentHash = "sha256-a"
	locked := lockfile.Lockfile{
		Version:     lockfile.Version,
		GeneratedAt: time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC),
		Generator:   "eyebrow/test",
		Artifacts: []lockfile.Entry{{
			Artifact: a,
			Approval: &lockfile.Approval{Status: "approved", By: "alice", Sig: "ed25519:forged"},
		}},
	}
	if err := store.Write(context.Background(), "eyebrowlock.json", locked); err != nil {
		t.Fatal(err)
	}
	svc := serviceWith(t, store, nil, fakeApprovalVerifier{err: errors.New("approval signature invalid")})

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json", CI: true,
		Policy: policy.Policy{RequireSignedApproval: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !hasViolation(res.Policy.Violations, "unsigned_approval", "approval signature invalid") {
		t.Errorf("expected a forged-approval violation, got %+v", res.Policy.Violations)
	}
}
