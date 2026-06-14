package trust

import (
	"testing"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/domain/lockfile"
)

func npmSource(integrity string) artifact.Source {
	return artifact.Source{Kind: artifact.SourceNPM, Ref: "1.2.3", Integrity: integrity}
}

func TestEvaluateCleanSignedIsTrusted(t *testing.T) {
	s := Evaluate(Input{Source: npmSource("sha512-AAA"), Signed: true, Drift: lockfile.DriftClassNone})
	if s.Verdict != Trusted {
		t.Fatalf("clean + pinned + signed → trusted, got %q (score %d)", s.Verdict, s.Value)
	}
	if s.Value != 100 {
		t.Fatalf("clean + signed caps at 100, got %d", s.Value)
	}
}

func TestEvaluateCriticalFindingQuarantines(t *testing.T) {
	s := Evaluate(Input{
		Source:   npmSource("sha512-AAA"),
		Findings: []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical}},
		Drift:    lockfile.DriftClassNone,
	})
	if s.Value != 60 || s.Verdict != Review {
		t.Fatalf("one critical → 60/review, got %d/%q", s.Value, s.Verdict)
	}
}

func TestEvaluateMutatedDriftIsHeaviest(t *testing.T) {
	s := Evaluate(Input{
		Source:   npmSource("sha512-AAA"),
		Findings: []finding.Finding{{RuleID: "SECRET", Severity: finding.SeverityHigh}},
		Drift:    lockfile.DriftClassMutated,
	})
	if s.Value != 50 || s.Verdict != Review {
		t.Fatalf("high + mutated → 50/review, got %d/%q", s.Value, s.Verdict)
	}
}

func TestEvaluateUnpinnedPenalty(t *testing.T) {
	s := Evaluate(Input{Source: npmSource(""), Drift: lockfile.DriftClassNone})
	if s.Value != 85 || s.Verdict != Trusted {
		t.Fatalf("unpinned npm → 85/trusted, got %d/%q", s.Value, s.Verdict)
	}
}

func TestEvaluateBroadCapabilityPenalty(t *testing.T) {
	s := Evaluate(Input{
		Source: npmSource("sha512-AAA"), Drift: lockfile.DriftClassNone,
		Exec: true, Network: true, SecretFilesystem: true,
	})
	if s.Value != 90 {
		t.Fatalf("broad caps → -10 → 90, got %d", s.Value)
	}
}

func TestEvaluateClampsAtZeroAndRecordsReasons(t *testing.T) {
	s := Evaluate(Input{
		Source: npmSource(""),
		Findings: []finding.Finding{
			{RuleID: "A", Severity: finding.SeverityCritical},
			{RuleID: "B", Severity: finding.SeverityCritical},
			{RuleID: "C", Severity: finding.SeverityCritical},
		},
		Drift: lockfile.DriftClassMutated,
	})
	if s.Value != 0 || s.Verdict != Quarantine {
		t.Fatalf("over-budget penalties clamp to 0/quarantine, got %d/%q", s.Value, s.Verdict)
	}
	if len(s.Reasons) == 0 {
		t.Fatalf("reasons must be recorded for the breakdown")
	}
}

func TestSensitivePaths(t *testing.T) {
	got := SensitivePaths([]string{"./workspace", "~/.aws/credentials", "~/.ssh", "/tmp/x"})
	if len(got) != 2 {
		t.Fatalf("expected 2 sensitive paths, got %v", got)
	}
}
