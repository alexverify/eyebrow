// Package risk fuses an artifact's static severity with its runtime usage
// (theme F3): a finding on code that has actually run is more urgent than the
// same finding on code that has only ever sat on disk. It turns the Findings
// view from "everything that could be bad" into "what is bad *and live*."
//
// Pure domain: the caller supplies the usage stat (from the audit log) and the
// finding severity; this package classifies liveness and ranks the fusion. It
// claims nothing it cannot know — an artifact with no telemetry path is
// Unknown, never falsely "dormant."
package risk

import (
	"time"

	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/usage"
)

// Liveness is how exercised an artifact is, by runtime evidence.
type Liveness string

const (
	// Live: invoked within LiveWindow — its risky paths are running now.
	Live Liveness = "live"
	// Exercised: invoked at some point, but not recently.
	Exercised Liveness = "exercised"
	// Unknown: no runtime signal. Either no telemetry path exists for this kind
	// (skills/plugins/hooks) or the server was never wrapped — we do not know,
	// so we do not pretend it is dormant.
	Unknown Liveness = "unknown"
)

// LiveWindow is how recently an artifact must have run to count as Live. A week
// matches a normal working cadence: used this sprint, not merely used once.
const LiveWindow = 7 * 24 * time.Hour

// Classify labels an artifact's liveness. found reports whether a usage stat
// was located for it (false for kinds with no telemetry, or servers never
// wrapped). Only positive evidence promotes above Unknown.
func Classify(st usage.Stat, found bool, now time.Time) Liveness {
	if !found || st.Count == 0 || st.LastUsed.IsZero() {
		return Unknown
	}
	if now.Sub(st.LastUsed) <= LiveWindow {
		return Live
	}
	return Exercised
}

// livenessBoost is the within-severity nudge for exercised risk. It is kept
// strictly smaller than one severity step (a Rank tier is 100) so liveness can
// never lift a finding above a genuinely more severe one.
func livenessBoost(l Liveness) int {
	switch l {
	case Live:
		return 30
	case Exercised:
		return 20
	default:
		return 0
	}
}

// Rank is the fused, sortable urgency of a finding: higher is more urgent.
// Severity dominates (each tier is worth 100); liveness orders findings that
// share a severity, so a live secret-access outranks a dormant one.
func Rank(sev finding.Severity, l Liveness) int {
	return sev.Rank()*100 + livenessBoost(l)
}
