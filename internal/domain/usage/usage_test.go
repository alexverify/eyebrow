package usage

import (
	"testing"
	"time"

	"github.com/alexverify/assay/internal/domain/audit"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestSummarizeCountsToolCallsPerServer(t *testing.T) {
	evs := []audit.Event{
		{Kind: audit.KindSessionStart, Server: "weather", At: ts("2026-06-01T10:00:00Z")},
		{Kind: audit.KindToolCall, Server: "weather", At: ts("2026-06-01T10:00:05Z"), Status: audit.StatusOK},
		{Kind: audit.KindToolCall, Server: "weather", At: ts("2026-06-03T09:00:00Z"), Status: audit.StatusOK},
		{Kind: audit.KindToolCall, Server: "prices", At: ts("2026-06-02T12:00:00Z"), Status: audit.StatusOK},
	}
	got := Summarize(evs)

	w, ok := got["weather"]
	if !ok {
		t.Fatalf("expected a stat for weather")
	}
	if w.Count != 2 {
		t.Errorf("weather Count = %d, want 2", w.Count)
	}
	if !w.FirstUsed.Equal(ts("2026-06-01T10:00:05Z")) {
		t.Errorf("weather FirstUsed = %v, want first tool_call", w.FirstUsed)
	}
	if !w.LastUsed.Equal(ts("2026-06-03T09:00:00Z")) {
		t.Errorf("weather LastUsed = %v, want last tool_call", w.LastUsed)
	}
	if got["prices"].Count != 1 {
		t.Errorf("prices Count = %d, want 1", got["prices"].Count)
	}
}

func TestSummarizeIgnoresNonInvocationEvents(t *testing.T) {
	// Session lifecycle and egress events are not invocations; they must not
	// inflate the count nor seed FirstUsed/LastUsed on their own.
	evs := []audit.Event{
		{Kind: audit.KindSessionStart, Server: "weather", At: ts("2026-06-01T10:00:00Z")},
		{Kind: audit.KindEgress, Server: "weather", At: ts("2026-06-01T10:00:01Z")},
		{Kind: audit.KindServerExit, Server: "weather", At: ts("2026-06-01T10:30:00Z")},
	}
	got := Summarize(evs)
	if _, ok := got["weather"]; ok {
		t.Errorf("a server with no tool calls must not appear in the summary")
	}
}

func TestSummarizeEmpty(t *testing.T) {
	if got := Summarize(nil); len(got) != 0 {
		t.Errorf("Summarize(nil) = %v, want empty", got)
	}
}

func TestAssessSleeperFires(t *testing.T) {
	// Installed 2026-04-01, never run, drifted, then first invoked 2026-06-01:
	// dormant ~61 days, then content mutated, then ran for the first time.
	sig := Assess(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		FirstUsed:   ts("2026-06-01T00:00:00Z"),
		Drifted:     true,
		Now:         ts("2026-06-02T00:00:00Z"),
	})
	if !sig.Sleeper {
		t.Fatalf("expected sleeper to fire for an old-install × drift × first-run triple")
	}
	if sig.DormantDays != 61 {
		t.Errorf("DormantDays = %d, want 61", sig.DormantDays)
	}
	if sig.Detail == "" {
		t.Errorf("expected a human detail string")
	}
}

func TestAssessNoSleeperWhenNotDrifted(t *testing.T) {
	// Same long dormancy and first run, but no drift → not the sleeper triple.
	sig := Assess(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		FirstUsed:   ts("2026-06-01T00:00:00Z"),
		Drifted:     false,
		Now:         ts("2026-06-02T00:00:00Z"),
	})
	if sig.Sleeper {
		t.Errorf("sleeper must not fire without content drift")
	}
}

func TestAssessNoSleeperWhenUsedPromptly(t *testing.T) {
	// Installed and invoked the same week, then drifted: not a dormant sleeper.
	sig := Assess(Input{
		InstalledAt: ts("2026-06-01T00:00:00Z"),
		FirstUsed:   ts("2026-06-03T00:00:00Z"),
		Drifted:     true,
		Now:         ts("2026-06-10T00:00:00Z"),
	})
	if sig.Sleeper {
		t.Errorf("sleeper must not fire when first use closely follows install")
	}
}

func TestAssessNoSleeperWhenNeverUsed(t *testing.T) {
	// Old install, drifted, but never invoked: dangerous but not yet the
	// "fired for the first time" signal F2 is about.
	sig := Assess(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		FirstUsed:   time.Time{},
		Drifted:     true,
		Now:         ts("2026-06-02T00:00:00Z"),
	})
	if sig.Sleeper {
		t.Errorf("sleeper requires a first invocation to have occurred")
	}
}

func TestAssessZeroInstallIsInconclusive(t *testing.T) {
	// Without an install time we cannot measure dormancy → never fire.
	sig := Assess(Input{
		InstalledAt: time.Time{},
		FirstUsed:   ts("2026-06-01T00:00:00Z"),
		Drifted:     true,
		Now:         ts("2026-06-02T00:00:00Z"),
	})
	if sig.Sleeper {
		t.Errorf("sleeper must not fire without a known install time")
	}
}
