package finding

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityInfo, 0},
		{Severity("bogus"), 0},
		{Severity(""), 0},
	}
	for _, tt := range tests {
		if got := tt.sev.Rank(); got != tt.want {
			t.Errorf("Severity(%q).Rank() = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	if !(SeverityCritical.Rank() > SeverityHigh.Rank() &&
		SeverityHigh.Rank() > SeverityMedium.Rank() &&
		SeverityMedium.Rank() > SeverityLow.Rank() &&
		SeverityLow.Rank() > SeverityInfo.Rank()) {
		t.Fatal("severity ranks are not strictly descending critical>high>medium>low>info")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		s, min Severity
		want   bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityInfo, SeverityInfo, true},
		{SeverityLow, SeverityInfo, true},
		{Severity("bogus"), SeverityLow, false},
		{Severity("bogus"), SeverityInfo, true}, // unknown ranks 0, info is 0
	}
	for _, tt := range tests {
		if got := tt.s.AtLeast(tt.min); got != tt.want {
			t.Errorf("Severity(%q).AtLeast(%q) = %v, want %v", tt.s, tt.min, got, tt.want)
		}
	}
}

func TestMax(t *testing.T) {
	if got := Max(nil); got != SeverityInfo {
		t.Errorf("Max(nil) = %q, want %q", got, SeverityInfo)
	}
	if got := Max([]Finding{}); got != SeverityInfo {
		t.Errorf("Max(empty) = %q, want %q", got, SeverityInfo)
	}
	fs := []Finding{
		{Severity: SeverityLow},
		{Severity: SeverityCritical},
		{Severity: SeverityMedium},
	}
	if got := Max(fs); got != SeverityCritical {
		t.Errorf("Max(mixed) = %q, want %q", got, SeverityCritical)
	}
	only := []Finding{{Severity: SeverityLow}, {Severity: SeverityInfo}}
	if got := Max(only); got != SeverityLow {
		t.Errorf("Max(low/info) = %q, want %q", got, SeverityLow)
	}
}
