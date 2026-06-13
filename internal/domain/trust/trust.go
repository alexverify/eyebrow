// Package trust turns the facts agentguard already knows about an artifact —
// its findings, how it drifted, whether its source is pinned, what it can do,
// and whether a trusted key approved it — into a single action-mapped Verdict
// plus a transparent, hand-recomputable breakdown.
//
// Like the rest of the domain core, it is pure: no IO, no third-party imports.
// The weights live here, in one place, so a user (or a test) can recompute any
// score by hand. The number is supporting evidence; the Verdict is the product.
package trust

import (
	"strings"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// Verdict is the single conclusion shown to the user, each mapping to an action.
type Verdict string

const (
	Trusted    Verdict = "trusted"    // ≥ trustedFloor: matches audit, verifiable
	Review     Verdict = "review"     // reviewFloor..trustedFloor: changed or unproven
	Quarantine Verdict = "quarantine" // < reviewFloor: recommend disabling
)

const (
	trustedFloor = 80
	reviewFloor  = 50
	maxScore     = 100
)

// Input is everything the verdict depends on. All of it already exists on the
// dashboard's per-artifact view, so Evaluate stays pure.
type Input struct {
	Findings         []finding.Finding
	Drift            lockfile.DriftClass
	Source           artifact.Source
	Signed           bool // approval signed by a trusted key
	Exec             bool
	Network          bool
	SecretFilesystem bool // declares access to a credential/secret path
}

// Reason is one additive contribution to the score, shown in the breakdown so
// the number is never a black box.
type Reason struct {
	Label string `json:"label"`
	Delta int    `json:"delta"`
}

// Score is the verdict plus its transparent derivation.
type Score struct {
	Value   int      `json:"value"`
	Verdict Verdict  `json:"verdict"`
	Reasons []Reason `json:"reasons"`
}

// Evaluate computes the trust score from a fixed additive model.
func Evaluate(in Input) Score {
	value := maxScore
	var reasons []Reason
	add := func(label string, delta int) {
		if delta == 0 {
			return
		}
		reasons = append(reasons, Reason{Label: label, Delta: delta})
		value += delta
	}

	for _, f := range in.Findings {
		add("finding: "+string(f.Severity)+" "+f.RuleID, -severityWeight(f.Severity))
	}
	if !pinned(in.Source) {
		add("source not pinned / unverifiable provenance", -15)
	}
	if in.Exec && in.Network && in.SecretFilesystem {
		add("broad capabilities: exec + network + secret-path read", -10)
	}
	if p := driftPenalty(in.Drift); p != 0 {
		add(driftLabel(in.Drift), -p)
	}
	if in.Signed {
		add("approved by a trusted key", +20)
	}

	if value < 0 {
		value = 0
	}
	if value > maxScore {
		value = maxScore
	}
	return Score{Value: value, Verdict: verdictFor(value), Reasons: reasons}
}

func severityWeight(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 40
	case finding.SeverityHigh:
		return 20
	case finding.SeverityMedium:
		return 8
	case finding.SeverityLow:
		return 2
	default:
		return 0
	}
}

func driftPenalty(d lockfile.DriftClass) int {
	switch d {
	case lockfile.DriftClassMutated:
		return 30
	case lockfile.DriftClassBroken:
		return 20
	case lockfile.DriftClassAdded:
		return 10
	case lockfile.DriftClassUpdated:
		return 5
	default:
		return 0
	}
}

func driftLabel(d lockfile.DriftClass) string {
	switch d {
	case lockfile.DriftClassMutated:
		return "content changed with no version bump (rug-pull shape)"
	case lockfile.DriftClassBroken:
		return "updated but integrity could not be verified"
	case lockfile.DriftClassAdded:
		return "new — never reviewed"
	case lockfile.DriftClassUpdated:
		return "updated to a new version"
	default:
		return ""
	}
}

// pinned reports whether the source carries a usable integrity anchor.
func pinned(s artifact.Source) bool {
	switch s.Kind {
	case artifact.SourceNPM:
		return s.Integrity != ""
	case artifact.SourceURL:
		return s.CertSPKI != ""
	case artifact.SourceGit, artifact.SourceLocal, artifact.SourceInline:
		return true
	default:
		return false
	}
}

func verdictFor(v int) Verdict {
	switch {
	case v >= trustedFloor:
		return Trusted
	case v >= reviewFloor:
		return Review
	default:
		return Quarantine
	}
}

// sensitiveMarkers are path fragments indicating access to credentials or keys
// unrelated to a normal workspace.
var sensitiveMarkers = []string{
	".ssh", ".aws", ".gnupg", "gcloud", ".kube",
	".env", "credentials", "id_rsa", ".npmrc", ".docker/config",
}

// SensitivePaths returns the subset of paths that touch known credential/secret
// locations. Used both to flag added filesystem capabilities and to set the
// SecretFilesystem input above.
func SensitivePaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		lower := strings.ToLower(p)
		for _, m := range sensitiveMarkers {
			if strings.Contains(lower, m) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
