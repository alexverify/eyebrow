package lockfile

import (
	"testing"
	"time"

	"github.com/agentguard/agentguard/internal/domain/artifact"
	"github.com/agentguard/agentguard/internal/domain/finding"
)

func art(name, hash string) artifact.Artifact {
	return artifact.Artifact{
		ID:          artifact.MakeID("claude-code", "project:.", artifact.TypeMCPServer, name),
		Tool:        "claude-code",
		Scope:       "project:.",
		Type:        artifact.TypeMCPServer,
		Name:        name,
		ContentHash: hash,
		Source:      artifact.Source{Kind: artifact.SourceLocal, Ref: "./" + name},
	}
}

var fixedTime = time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)

func buildOne(a artifact.Artifact) Lockfile {
	return Build([]artifact.Artifact{a}, fixedTime, "agentguard/test")
}

func TestBuildSortsByID(t *testing.T) {
	a := art("zebra", "sha256-1")
	b := art("alpha", "sha256-2")
	lf := Build([]artifact.Artifact{a, b}, fixedTime, "agentguard/test")
	if lf.Artifacts[0].ID > lf.Artifacts[1].ID {
		t.Fatalf("entries not sorted by ID: %q then %q", lf.Artifacts[0].ID, lf.Artifacts[1].ID)
	}
	if lf.Version != Version {
		t.Fatalf("Version = %d, want %d", lf.Version, Version)
	}
}

func TestCompareNoDrift(t *testing.T) {
	a := art("srv", "sha256-aaa")
	d := Compare(buildOne(a), buildOne(a))
	if d.HasDrift() {
		t.Fatalf("identical snapshots must not drift, got %+v", d.Changes)
	}
}

func TestCompareContentChanged(t *testing.T) {
	locked := buildOne(art("srv", "sha256-old"))
	current := buildOne(art("srv", "sha256-new"))
	d := Compare(locked, current)
	if len(d.Changes) != 1 || d.Changes[0].Kind != DriftContentChanged {
		t.Fatalf("expected one content_changed, got %+v", d.Changes)
	}
	if d.Changes[0].Old != "sha256-old" || d.Changes[0].New != "sha256-new" {
		t.Fatalf("old/new not captured: %+v", d.Changes[0])
	}
}

func TestCompareAddedAndRemoved(t *testing.T) {
	locked := buildOne(art("gone", "sha256-x"))
	current := buildOne(art("fresh", "sha256-y"))
	d := Compare(locked, current)
	kinds := map[DriftKind]bool{}
	for _, c := range d.Changes {
		kinds[c.Kind] = true
	}
	if !kinds[DriftAdded] || !kinds[DriftRemoved] {
		t.Fatalf("expected added and removed, got %+v", d.Changes)
	}
}

func TestCompareVersionAndIntegrityAndCert(t *testing.T) {
	base := art("srv", "sha256-same")
	base.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "srv@1.0.0", Integrity: "sha512-a", CertSPKI: "spki-a"}
	moved := art("srv", "sha256-same")
	moved.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "srv@1.0.1", Integrity: "sha512-b", CertSPKI: "spki-b"}

	d := Compare(buildOne(base), buildOne(moved))
	kinds := map[DriftKind]bool{}
	for _, c := range d.Changes {
		kinds[c.Kind] = true
	}
	for _, want := range []DriftKind{DriftVersionChanged, DriftIntegrityChanged, DriftCertRotated} {
		if !kinds[want] {
			t.Fatalf("expected %s in changes, got %+v", want, d.Changes)
		}
	}
}

func TestCompareIsDeterministic(t *testing.T) {
	locked := Build([]artifact.Artifact{art("a", "h1"), art("b", "h2")}, fixedTime, "g")
	current := Build([]artifact.Artifact{art("a", "h1x"), art("b", "h2x")}, fixedTime, "g")
	first := Compare(locked, current)
	for i := 0; i < 5; i++ {
		got := Compare(locked, current)
		if len(got.Changes) != len(first.Changes) {
			t.Fatal("Compare not deterministic in length")
		}
		for j := range got.Changes {
			if got.Changes[j] != first.Changes[j] {
				t.Fatalf("Compare not deterministic at %d: %+v vs %+v", j, got.Changes[j], first.Changes[j])
			}
		}
	}
}

func TestNewFindingsAtThreshold(t *testing.T) {
	prev := art("srv", "h")
	prev.Findings = []finding.Finding{{RuleID: "OLD", Severity: finding.SeverityHigh, File: "a.js", Line: 1}}

	cur := art("srv", "h")
	cur.Findings = []finding.Finding{
		{RuleID: "OLD", Severity: finding.SeverityHigh, File: "a.js", Line: 1}, // unchanged, must not re-report
		{RuleID: "NEW-RCE", Severity: finding.SeverityCritical, File: "b.js", Line: 9},
		{RuleID: "NOISE", Severity: finding.SeverityLow, File: "c.js", Line: 3}, // below threshold
	}

	got := NewFindings(buildOne(prev), buildOne(cur), finding.SeverityHigh)
	if len(got) != 1 || got[0].RuleID != "NEW-RCE" {
		t.Fatalf("expected only the new critical finding, got %+v", got)
	}
}
