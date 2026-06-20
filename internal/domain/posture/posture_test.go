package posture

import (
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

func art(id, tool, name, hash string, src artifact.Source, fs ...finding.Finding) artifact.Artifact {
	return artifact.Artifact{ID: id, Tool: tool, Type: artifact.TypeSkill, Name: name, ContentHash: hash, Source: src, Findings: fs}
}

func lf(arts ...artifact.Artifact) lockfile.Lockfile {
	return lockfile.Build(arts, time.Unix(1000, 0).UTC(), "eyebrow/test")
}

func TestSummarizeCountsVerdictsAndTools(t *testing.T) {
	clean := art("a", "claude-code", "linter", "h1",
		artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"})
	risky := art("b", "cursor", "evil", "h2",
		artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-B"},
		finding.Finding{RuleID: "RCE", Severity: finding.SeverityCritical},
		finding.Finding{RuleID: "EXFIL", Severity: finding.SeverityCritical})

	p := Summarize(lf(clean, risky), lockfile.Lockfile{}, nil, time.Unix(2000, 0).UTC())
	if p.Total != 2 || p.Tools != 2 {
		t.Fatalf("total/tools = %d/%d, want 2/2", p.Total, p.Tools)
	}
	if p.Trusted != 1 {
		t.Errorf("clean npm artifact should be trusted: %+v", p)
	}
	if p.Quarantine != 1 {
		t.Errorf("critical-finding artifact should be quarantine-recommended: %+v", p)
	}
	if p.Drifted != 0 {
		t.Errorf("first run has no drift: %+v", p)
	}
}

func TestSummarizeCountsDrift(t *testing.T) {
	src := artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	locked := lf(art("a", "claude-code", "db", "old", src))
	// same version, different bytes → mutated (rug pull)
	current := lf(art("a", "claude-code", "db", "NEW", src))

	p := Summarize(current, locked, nil, time.Unix(2000, 0).UTC())
	if p.Drifted != 1 {
		t.Errorf("a same-version content change should count as drifted: %+v", p)
	}
}

func TestPostureLine(t *testing.T) {
	p := Posture{Total: 21, Tools: 3, Trusted: 18, Review: 2, Quarantine: 1}
	got := p.Line()
	if got == "" {
		t.Fatal("Line should not be empty")
	}
	if want := "Scanned 21 artifact(s) across 3 tool(s)."; got[:len(want)] != want {
		t.Errorf("Line = %q", got)
	}
}
