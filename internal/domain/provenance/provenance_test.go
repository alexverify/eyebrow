package provenance

import (
	"testing"

	"github.com/alexverify/agentguard/internal/domain/artifact"
)

func TestAssessNpmPinnedSignedReachesLevel3(t *testing.T) {
	l := Assess(artifact.Source{Kind: artifact.SourceNPM, Ref: "1.2.3", Integrity: "sha512-A"}, true)
	if l.Max != 4 {
		t.Fatalf("max rungs = %d, want 4", l.Max)
	}
	// pinned ✓ integrity ✓ signed ✓ publisher ✗ → level 3
	if l.Level != 3 {
		t.Fatalf("pinned+integrity+signed npm → level 3, got %d (%+v)", l.Level, l.Rungs)
	}
}

func TestAssessUnpinnedStopsAtZero(t *testing.T) {
	l := Assess(artifact.Source{Kind: artifact.SourceNPM}, true)
	if l.Level != 0 {
		t.Fatalf("no ref → level 0, got %d", l.Level)
	}
}

func TestAssessNpmWithoutIntegrityStopsAtOne(t *testing.T) {
	l := Assess(artifact.Source{Kind: artifact.SourceNPM, Ref: "1.2.3"}, true)
	// pinned ✓ integrity ✗ → the chain breaks at integrity, level 1
	if l.Level != 1 {
		t.Fatalf("pinned but no integrity → level 1, got %d", l.Level)
	}
}

func TestAssessLocalSourceIsAnchored(t *testing.T) {
	l := Assess(artifact.Source{Kind: artifact.SourceLocal, Ref: "./x"}, false)
	// pinned ✓ integrity ✓ (content-addressed) signed ✗ → level 2
	if l.Level != 2 {
		t.Fatalf("local pinned+anchored, unsigned → level 2, got %d (%+v)", l.Level, l.Rungs)
	}
}
