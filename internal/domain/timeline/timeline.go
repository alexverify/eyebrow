// Package timeline assembles the per-artifact event ribbon (theme F4): the
// unified "what happened, when" stream a reviewer wants in an incident —
// installed → approved → first invoked → drifted → last invoked — ordered in
// time. The drawer otherwise shows only current state, not history.
//
// Like the rest of the domain core it is pure: the caller gathers the
// timestamped facts (install mtime, approval time, first/last use from the
// audit log, when drift was detected) and Build orders and labels them. It
// fabricates nothing — an event with no known time is simply omitted, so the
// ribbon never implies precision eyebrow does not have.
package timeline

import (
	"fmt"
	"sort"
	"time"
)

// Kind names a milestone in an artifact's life.
type Kind string

const (
	KindInstalled Kind = "installed"
	KindApproved  Kind = "approved"
	KindFirstUsed Kind = "first_used"
	KindLastUsed  Kind = "last_used"
	KindDrifted   Kind = "drifted"
)

// Severity drives the dot color in the ribbon. It mirrors the dashboard scale.
type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityInfo     Severity = "info"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event is one dot on the ribbon.
type Event struct {
	At       time.Time `json:"at"`
	Kind     Kind      `json:"kind"`
	Label    string    `json:"label"`
	Detail   string    `json:"detail,omitempty"`
	Severity Severity  `json:"severity"`
}

// Input is the timestamped facts the ribbon is built from. Every field is
// already assembled on the dashboard's per-artifact view, so Build stays pure.
// Zero-value times mean "unknown" and drop the corresponding event.
type Input struct {
	InstalledAt time.Time // file mtime — when the artifact first appeared
	ApprovedAt  time.Time // signed approval timestamp
	ApprovedBy  string
	FirstUsed   time.Time // first observed invocation (audit log)
	LastUsed    time.Time // most recent invocation
	UseCount    int
	DriftedAt   time.Time // when drift was detected (the scan time); zero if none
	DriftDetail string    // the human one-liner for the drift
	DriftDanger bool      // unexplained/unverifiable drift → critical, else benign update
}

// Build returns the ordered event ribbon. Events whose time is zero are
// omitted, and a "last invoked" that coincides with "first invoked" (a single
// call) is dropped as redundant.
func Build(in Input) []Event {
	var evs []Event
	add := func(at time.Time, k Kind, label, detail string, sev Severity) {
		if at.IsZero() {
			return
		}
		evs = append(evs, Event{At: at, Kind: k, Label: label, Detail: detail, Severity: sev})
	}

	add(in.InstalledAt, KindInstalled, "Installed", "", SeverityInfo)

	approvedDetail := ""
	if in.ApprovedBy != "" {
		approvedDetail = "by " + in.ApprovedBy
	}
	add(in.ApprovedAt, KindApproved, "Approved", approvedDetail, SeverityOK)

	add(in.FirstUsed, KindFirstUsed, "First invoked", "", SeverityInfo)

	driftSev := SeverityInfo
	if in.DriftDanger {
		driftSev = SeverityCritical
	}
	add(in.DriftedAt, KindDrifted, "Drift detected", in.DriftDetail, driftSev)

	if in.LastUsed.After(in.FirstUsed) {
		detail := ""
		if in.UseCount > 0 {
			detail = fmt.Sprintf("%d invocations total", in.UseCount)
		}
		add(in.LastUsed, KindLastUsed, "Last invoked", detail, SeverityInfo)
	}

	sort.SliceStable(evs, func(i, j int) bool { return evs[i].At.Before(evs[j].At) })
	return evs
}
