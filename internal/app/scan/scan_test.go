package scan_test

import (
	"context"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/apptest"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
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

func newService(d scan.Deps) *scan.Service {
	d.Clock = apptest.FixedClock{T: time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)}
	d.Generator = "eyebrow/test"
	return scan.New(d)
}

func TestScanEnrichesAndPersists(t *testing.T) {
	store := apptest.NewLockStore()
	svc := newService(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("srv")}},
		Resolver:   apptest.Resolver{}, // echoes Ref as LocalPath
		Hasher:     apptest.Hasher{HashValue: "sha256-deadbeef"},
		Analyzer: apptest.Analyzer{Findings: []finding.Finding{
			{RuleID: "EXEC-CHILD-PROCESS", Severity: finding.SeverityMedium, OWASP: "ASK-03"},
		}},
		Lock:     store,
		Reporter: apptest.Reporter{},
	})

	lf, err := svc.Run(context.Background(), scan.Options{
		Scopes:       []ports.Scope{{Kind: "project", Path: "."}},
		LockfilePath: "eyebrowlock.json",
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(lf.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(lf.Artifacts))
	}
	got := lf.Artifacts[0]
	if got.ContentHash != "sha256-deadbeef" {
		t.Errorf("ContentHash = %q, want sha256-deadbeef", got.ContentHash)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "EXEC-CHILD-PROCESS" {
		t.Errorf("findings not attached: %+v", got.Findings)
	}
	if !store.Exists("eyebrowlock.json") {
		t.Error("lockfile was not persisted")
	}
	if lf.Generator != "eyebrow/test" {
		t.Errorf("Generator = %q", lf.Generator)
	}
}

func TestScanDegradesOnUnsupportedSource(t *testing.T) {
	svc := newService(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("remote")}},
		Resolver: apptest.Resolver{Func: func(artifact.Source) (ports.Resolution, error) {
			return ports.Resolution{}, ports.ErrUnsupported
		}},
		Hasher:   apptest.Hasher{},
		Analyzer: apptest.Analyzer{},
		Lock:     apptest.NewLockStore(),
		Reporter: apptest.Reporter{},
	})

	lf, err := svc.Build(context.Background(), nil)
	if err != nil {
		t.Fatalf("Build must not fail on unsupported source: %v", err)
	}
	got := lf.Artifacts[0]
	if got.ContentHash != "" {
		t.Errorf("unsupported source should not produce a content hash, got %q", got.ContentHash)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "RESOLVE-UNSUPPORTED" {
		t.Errorf("expected a RESOLVE-UNSUPPORTED finding, got %+v", got.Findings)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	build := func() string {
		svc := newService(scan.Deps{
			Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("b"), mcp("a")}},
			Resolver:   apptest.Resolver{},
			Hasher:     apptest.Hasher{HashValue: "sha256-x"},
			Analyzer:   apptest.Analyzer{},
			Lock:       apptest.NewLockStore(),
			Reporter:   apptest.Reporter{},
		})
		lf, err := svc.Build(context.Background(), nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		// IDs are sorted, so the first entry must be stable across runs.
		return lf.Artifacts[0].ID + lf.Artifacts[1].ID
	}
	if build() != build() {
		t.Fatal("scan output is not deterministic")
	}
}

func TestScanFlagsKnownMaliciousArtifact(t *testing.T) {
	svc := newService(scan.Deps{
		Discoverer: apptest.Discoverer{Artifacts: []artifact.Artifact{mcp("postmark-mcp")}},
		Resolver:   apptest.Resolver{},
		Hasher:     apptest.Hasher{HashValue: "sha256-deadbeef"},
		Analyzer:   apptest.Analyzer{},
		Lock:       apptest.NewLockStore(),
		Reporter:   apptest.Reporter{},
	})
	lf, err := svc.Build(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range lf.Artifacts[0].Findings {
		if f.RuleID == "ADVISORY-postmark-mcp-bcc" && f.Severity == finding.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Fatalf("postmark-mcp should carry the advisory finding, got %+v", lf.Artifacts[0].Findings)
	}
}
