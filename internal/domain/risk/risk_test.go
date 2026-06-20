package risk

import (
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/usage"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestClassifyLiveWhenRecentlyInvoked(t *testing.T) {
	now := ts("2026-06-10T00:00:00Z")
	st := usage.Stat{Count: 5, LastUsed: now.Add(-2 * 24 * time.Hour)}
	if got := Classify(st, true, now); got != Live {
		t.Errorf("recent invocation should be Live, got %q", got)
	}
}

func TestClassifyExercisedWhenStale(t *testing.T) {
	now := ts("2026-06-10T00:00:00Z")
	st := usage.Stat{Count: 5, LastUsed: now.Add(-30 * 24 * time.Hour)}
	if got := Classify(st, true, now); got != Exercised {
		t.Errorf("old invocation should be Exercised, got %q", got)
	}
}

func TestClassifyUnknownWhenNoTelemetry(t *testing.T) {
	now := ts("2026-06-10T00:00:00Z")
	// found=false: a skill (no telemetry path) or an MCP server that was never
	// wrapped — we cannot claim it is dormant, only that we have no signal.
	if got := Classify(usage.Stat{}, false, now); got != Unknown {
		t.Errorf("absent telemetry should be Unknown, got %q", got)
	}
}

func TestRankSeverityDominatesLiveness(t *testing.T) {
	// A dormant critical must still outrank a live high — liveness sharpens
	// ordering within a severity, it does not override the severity itself.
	critDormant := Rank(finding.SeverityCritical, Unknown)
	highLive := Rank(finding.SeverityHigh, Live)
	if critDormant <= highLive {
		t.Errorf("critical/unknown (%d) should outrank high/live (%d)", critDormant, highLive)
	}
}

func TestRankLivenessOrdersWithinSeverity(t *testing.T) {
	live := Rank(finding.SeverityHigh, Live)
	exercised := Rank(finding.SeverityHigh, Exercised)
	unknown := Rank(finding.SeverityHigh, Unknown)
	if !(live > exercised && exercised > unknown) {
		t.Errorf("within a severity: live(%d) > exercised(%d) > unknown(%d)", live, exercised, unknown)
	}
}
