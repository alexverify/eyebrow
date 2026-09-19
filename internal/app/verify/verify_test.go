package verify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/apptest"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/app/verify"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

func mcp(name string) artifact.Artifact {
	return artifact.Artifact{
		ID:     artifact.MakeID("claude-code", "project:.", artifact.TypeMCPServer, name),
		Tool:   "claude-code",
		Scope:  "project:.",
		Type:   artifact.TypeMCPServer,
		Name:   name,
		Source: artifact.Source{Kind: artifact.SourceLocal, Ref: "/tmp/" + name},
	}
}

// harness wires a scan builder and a verify service that share one lock store,
// with the hasher's value controllable to simulate content drift.
func harness(t *testing.T, hash string, findings []finding.Finding) (*verify.Service, *apptest.LockStore) {
	t.Helper()
	store := apptest.NewLockStore()
	builder := scan.New(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("srv")}},
		Resolver:   apptest.Resolver{},
		Hasher:     apptest.Hasher{HashValue: hash},
		Analyzer:   apptest.Analyzer{Findings: findings},
		Lock:       store,
		Reporter:   apptest.Reporter{},
		Clock:      apptest.FixedClock{T: time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)},
		Generator:  "eyebrow/test",
	})
	svc := verify.New(verify.Deps{Builder: builder, Lock: store, Reporter: apptest.Reporter{}})
	return svc, store
}

func seed(t *testing.T, store *apptest.LockStore, hash string, findings []finding.Finding) {
	t.Helper()
	builder := scan.New(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("srv")}},
		Resolver:   apptest.Resolver{},
		Hasher:     apptest.Hasher{HashValue: hash},
		Analyzer:   apptest.Analyzer{Findings: findings},
		Lock:       store,
		Reporter:   apptest.Reporter{},
		Clock:      apptest.FixedClock{T: time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)},
		Generator:  "eyebrow/test",
	})
	if _, err := builder.Run(context.Background(), scan.Options{LockfilePath: "eyebrowlock.json"}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestVerifyNoLockfile(t *testing.T) {
	svc, _ := harness(t, "sha256-a", nil)
	_, err := svc.Run(context.Background(), verify.Options{LockfilePath: "eyebrowlock.json"}, nil)
	if !errors.Is(err, ports.ErrNoLockfile) {
		t.Fatalf("want ErrNoLockfile, got %v", err)
	}
}

func TestVerifyCleanWhenUnchanged(t *testing.T) {
	svc, store := harness(t, "sha256-a", nil)
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "eyebrowlock.json"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK || res.Diff.HasDrift() {
		t.Fatalf("expected clean verify, got %+v", res)
	}
}

func TestVerifyDetectsContentDrift(t *testing.T) {
	// Locked at hash -a, but the environment now hashes to -b: a rug pull.
	svc, store := harness(t, "sha256-b", nil)
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "eyebrowlock.json"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK || !res.Diff.HasDrift() {
		t.Fatalf("expected drift, got %+v", res)
	}
}

// With AllowContentDrift, a bare content-hash change in CI must NOT fail the
// gate — only policy violations decide. This is the prose-catalog contract
// (skills edited routinely) where content drift alone is not a security event.
func TestVerifyCIAllowsContentDriftWhenPolicySaysSo(t *testing.T) {
	svc, store := harness(t, "sha256-b", nil) // hashes differently from the lock
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{
		LockfilePath: "eyebrowlock.json",
		CI:           true,
		Policy:       policy.Policy{AllowContentDrift: true},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Diff.HasDrift() {
		t.Fatal("drift should still be detected and reported")
	}
	if !res.OK {
		t.Fatalf("content drift must not fail the gate under AllowContentDrift, got %+v", res.Policy.Violations)
	}
}

func TestVerifyCIGatesOnNewCriticalFinding(t *testing.T) {
	// Same content hash (no drift), but a new critical finding appears.
	crit := []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical, File: "x.js", Line: 1}}
	svc, store := harness(t, "sha256-a", crit)
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "eyebrowlock.json", CI: true}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK {
		t.Fatal("CI verify must fail when a new critical finding appears")
	}
	if len(res.Policy.Violations) != 1 || res.Policy.Violations[0].RuleID != "RCE" {
		t.Fatalf("expected 1 RCE policy violation, got %+v", res.Policy.Violations)
	}
}

func TestCheckDetectsDriftWithoutReadingAStore(t *testing.T) {
	svc, store := harness(t, "sha256:new", nil)
	seed(t, store, "sha256:old", nil)
	locked, err := store.Read(context.Background(), "eyebrowlock.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Check(context.Background(), locked, verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected drift, got OK")
	}
	if len(res.Diff.Changes) != 1 || res.Diff.Changes[0].Kind != lockfile.DriftContentChanged {
		t.Fatalf("unexpected diff: %+v", res.Diff)
	}
}

func TestCheckAppliesPolicyInCIMode(t *testing.T) {
	high := []finding.Finding{{RuleID: "X", Severity: finding.SeverityHigh}}
	svc, store := harness(t, "sha256:same", high)
	seed(t, store, "sha256:same", nil)
	locked, err := store.Read(context.Background(), "eyebrowlock.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Check(context.Background(), locked, verify.Options{CI: true, Policy: policy.Default()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a new high finding must fail the CI gate")
	}
	if len(res.Policy.Violations) != 1 || res.Policy.Violations[0].Kind != "finding" {
		t.Fatalf("unexpected violations: %+v", res.Policy.Violations)
	}
}
