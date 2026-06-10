package verify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/app/apptest"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/app/scan"
	"github.com/alexverify/agentguard/internal/app/verify"
	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
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
		Generator:  "agentguard/test",
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
		Generator:  "agentguard/test",
	})
	if _, err := builder.Run(context.Background(), scan.Options{LockfilePath: "agentlock.json"}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestVerifyNoLockfile(t *testing.T) {
	svc, _ := harness(t, "sha256-a", nil)
	_, err := svc.Run(context.Background(), verify.Options{LockfilePath: "agentlock.json"}, nil)
	if !errors.Is(err, ports.ErrNoLockfile) {
		t.Fatalf("want ErrNoLockfile, got %v", err)
	}
}

func TestVerifyCleanWhenUnchanged(t *testing.T) {
	svc, store := harness(t, "sha256-a", nil)
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "agentlock.json"}, nil)
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

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "agentlock.json"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK || !res.Diff.HasDrift() {
		t.Fatalf("expected drift, got %+v", res)
	}
}

func TestVerifyCIGatesOnNewCriticalFinding(t *testing.T) {
	// Same content hash (no drift), but a new critical finding appears.
	crit := []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical, File: "x.js", Line: 1}}
	svc, store := harness(t, "sha256-a", crit)
	seed(t, store, "sha256-a", nil)

	res, err := svc.Run(context.Background(), verify.Options{LockfilePath: "agentlock.json", CI: true}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK {
		t.Fatal("CI verify must fail when a new critical finding appears")
	}
	if len(res.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %+v", res.NewFindings)
	}
}
