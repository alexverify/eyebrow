// Package finding models the output of static analysis over an artifact.
//
// It is part of the pure domain core: no IO, no external dependencies. The
// analysis adapters (native matchers, the Semgrep runner) produce values of
// these types; the application and reporting layers consume them.
package finding

// Severity ranks a finding's risk. Ordering matters for policy thresholds
// (e.g. "fail CI on new critical/high"), so use Rank for comparisons rather
// than comparing the string values directly.
type Severity string

const (
	// SeverityCritical marks remote code execution or data exfiltration.
	SeverityCritical Severity = "critical"
	// SeverityHigh marks sensitive-path reads or unpinned remote sources.
	SeverityHigh Severity = "high"
	// SeverityMedium marks the presence of execution primitives.
	SeverityMedium Severity = "medium"
	// SeverityLow marks weak or contextual signals.
	SeverityLow Severity = "low"
	// SeverityInfo marks informational findings with no inherent risk.
	SeverityInfo Severity = "info"
)

// Rank returns a numeric weight where higher means more severe. Unknown
// severities rank as 0 so they never satisfy an AtLeast threshold by accident.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return s.Rank() >= min.Rank()
}

// Finding is a single static-analysis result mapped to the OWASP Agentic
// Skills Top 10 taxonomy for consistent, credible severity.
//
// See https://owasp.org/www-project-agentic-skills-top-10/ for the OWASP field.
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	OWASP       string   `json:"owasp,omitempty"` // e.g. "ASK-03"
	File        string   `json:"file,omitempty"`  // POSIX-relative to the artifact root
	Line        int      `json:"line,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	Explanation string   `json:"explanation,omitempty"`
}

// Max returns the highest severity among the findings, or SeverityInfo when
// the slice is empty.
func Max(fs []Finding) Severity {
	worst := SeverityInfo
	for _, f := range fs {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}
