// Package posture summarizes an inventory into a single trust verdict and the
// counts behind it — the onboarding "first verdict" and the data point a trend
// is built from. It is pure domain: counts only, never content, so a history of
// snapshots leaks nothing about the artifacts themselves.
package posture

import (
	"fmt"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/trust"
)

// Posture is a counts-only snapshot of an inventory's trust standing.
type Posture struct {
	At         time.Time `json:"at"`
	Total      int       `json:"total"`
	Tools      int       `json:"tools"`
	Trusted    int       `json:"trusted"`
	Review     int       `json:"review"`
	Quarantine int       `json:"quarantine"`
	Drifted    int       `json:"drifted"` // mutated/broken since the locked snapshot
}

// Summarize rolls the current inventory (diffed against the locked snapshot) up
// into a posture. approved holds the IDs whose approval is trusted; at is the
// snapshot time. It mirrors the dashboard's verdict logic so the terminal and
// the dashboard agree.
func Summarize(current, locked lockfile.Lockfile, approved map[string]bool, at time.Time) Posture {
	classes := lockfile.Classify(locked, current)
	lockedByID := make(map[string]lockfile.Entry, len(locked.Artifacts))
	for _, e := range locked.Artifacts {
		lockedByID[e.ID] = e
	}

	p := Posture{At: at, Total: len(current.Artifacts)}
	tools := map[string]bool{}
	for _, e := range current.Artifacts {
		tools[e.Tool] = true
		class := classes[e.ID]
		if class == lockfile.DriftClassMutated || class == lockfile.DriftClassBroken {
			p.Drifted++
		}

		score := trust.Evaluate(trust.Input{
			Findings:         e.Findings,
			Drift:            class,
			Source:           e.Source,
			Signed:           approved[e.ID],
			Exec:             e.Capabilities.Exec,
			Network:          len(e.Capabilities.Network) > 0,
			SecretFilesystem: len(trust.SensitivePaths(e.Capabilities.Filesystem)) > 0,
		})
		verdict := score.Verdict
		if lockedByID[e.ID].Quarantined {
			verdict = trust.Quarantine
		}
		switch verdict {
		case trust.Trusted:
			p.Trusted++
		case trust.Review:
			p.Review++
		case trust.Quarantine:
			p.Quarantine++
		}
	}
	p.Tools = len(tools)
	return p
}

// ApprovedSet returns the IDs whose approval is signed-and-approved — the
// "trusted approval" input Summarize expects.
func ApprovedSet(lf lockfile.Lockfile) map[string]bool {
	out := map[string]bool{}
	for _, e := range lf.Artifacts {
		if e.Approval != nil && e.Approval.Status == "approved" && e.Approval.Sig != "" {
			out[e.ID] = true
		}
	}
	return out
}

// Line renders the one-line verdict for the terminal (the first-run summary).
func (p Posture) Line() string {
	drift := "nothing has drifted"
	if p.Drifted == 1 {
		drift = "1 artifact has drifted"
	} else if p.Drifted > 1 {
		drift = fmt.Sprintf("%d artifacts have drifted", p.Drifted)
	}
	return fmt.Sprintf("Scanned %d artifact(s) across %d tool(s). %d trusted, %d need review, %d quarantine-recommended — %s.",
		p.Total, p.Tools, p.Trusted, p.Review, p.Quarantine, drift)
}
