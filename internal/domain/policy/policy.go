// Package policy defines the rules a team can enforce over an inventory, and
// the pure evaluation that turns a locked + current snapshot into a pass/fail
// decision. It is part of the domain core: no IO. Loading the policy file lives
// in the policystore adapter.
package policy

import (
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// Policy is the team-configurable gate applied by `verify --ci`.
type Policy struct {
	// FailOnSeverity is the lowest severity of a newly introduced finding that
	// fails the gate (default: high).
	FailOnSeverity finding.Severity `json:"failOnSeverity,omitempty"`
	// IgnoreRules suppresses specific rule IDs (accepted false positives).
	IgnoreRules []string `json:"ignoreRules,omitempty"`
	// Mutes suppresses rule IDs like IgnoreRules but records a rationale and the
	// muter, so an accepted false positive is auditable in the committed policy
	// rather than silently dropped.
	Mutes []Mute `json:"mutes,omitempty"`
	// RequireApproval fails any artifact not marked approved in the lockfile.
	RequireApproval bool `json:"requireApproval,omitempty"`
	// RequireSignedApproval additionally fails any approval lacking a valid
	// signature from a trusted key. Implies RequireApproval.
	RequireSignedApproval bool `json:"requireSignedApproval,omitempty"`
	// RequireSignature fails when the lockfile carries no valid signature.
	RequireSignature bool `json:"requireSignature,omitempty"`
	// BlockPublishers fails any artifact whose source ref contains one of these
	// substrings (e.g. a domain or org). Case-insensitive.
	BlockPublishers []string `json:"blockPublishers,omitempty"`
	// BlockArtifacts fails any artifact whose name contains one of these
	// substrings. Case-insensitive.
	BlockArtifacts []string `json:"blockArtifacts,omitempty"`
	// AllowPublishers, when non-empty, fails any artifact whose source ref does
	// not contain one of these substrings — a publisher allowlist.
	AllowPublishers []string `json:"allowPublishers,omitempty"`
	// MCP constrains tool calls at runtime, enforced by the mcp-shim
	// (see DecideTool in mcp.go). Not used by verify.
	MCP MCPPolicy `json:"mcp,omitempty"`
	// Fleet configures the team-wide CI gate (`eyebrow fleet verify`). Not used by
	// the single-machine verify.
	Fleet FleetPolicy `json:"fleet,omitempty"`
}

// FleetPolicy tunes the cross-machine CI gate. It lives in the committed policy
// so the team reviews the threshold like any other rule.
type FleetPolicy struct {
	// MaxBlastRadius fails the fleet gate when a drifted or quarantined artifact
	// is installed on more than this many machines. Zero disables the reach
	// check (machine conformance still gates).
	MaxBlastRadius int `json:"maxBlastRadius,omitempty"`
}

// Mute suppresses a finding rule with a recorded rationale. It suppresses the
// rule exactly like an IgnoreRules entry; the Reason and By fields make the
// suppression reviewable in the committed policy diff.
type Mute struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason,omitempty"`
	By     string `json:"by,omitempty"`
}

// Default is the policy used when no policy file is present.
func Default() Policy {
	return Policy{FailOnSeverity: finding.SeverityHigh}
}

// Normalize fills defaults for zero-value fields so a partial policy file is
// still well-defined.
func (p Policy) Normalize() Policy {
	if p.FailOnSeverity == "" {
		p.FailOnSeverity = finding.SeverityHigh
	}
	if p.RequireSignedApproval {
		p.RequireApproval = true // a signed approval is still an approval
	}
	return p
}

// Violation is a single reason the gate failed.
type Violation struct {
	Kind     string           `json:"kind"` // finding|unapproved|quarantined|frozen_drift|blocked_publisher|blocked_artifact|not_allowlisted
	ID       string           `json:"id,omitempty"`
	Name     string           `json:"name,omitempty"`
	RuleID   string           `json:"ruleId,omitempty"`
	Severity finding.Severity `json:"severity,omitempty"`
	Detail   string           `json:"detail,omitempty"`
}

// Result is the outcome of evaluating a policy.
type Result struct {
	Violations []Violation `json:"violations"`
}

// OK reports whether the gate passed.
func (r Result) OK() bool { return len(r.Violations) == 0 }

// containsAny reports the first needle (lowercased) that is a substring of the
// already-lowercased haystack. Empty needles are skipped.
func containsAny(haystack string, needles []string) (string, bool) {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(n)) {
			return n, true
		}
	}
	return "", false
}

// Evaluate gates the current snapshot against the policy, relative to the
// locked snapshot. "New" findings are those not already present in locked, so
// previously accepted issues don't re-fail a build.
func Evaluate(p Policy, locked, current lockfile.Lockfile) Result {
	p = p.Normalize()

	ignored := make(map[string]bool, len(p.IgnoreRules)+len(p.Mutes))
	for _, r := range p.IgnoreRules {
		ignored[r] = true
	}
	for _, m := range p.Mutes {
		ignored[m.Rule] = true
	}

	// Per-finding "flagged safe" sign-offs live on the locked entry; an acked
	// finding is an accepted false positive and does not fail the gate.
	safe := make(map[string]map[string]bool, len(locked.Artifacts))
	for _, e := range locked.Artifacts {
		if len(e.SafeFindings) == 0 {
			continue
		}
		m := make(map[string]bool, len(e.SafeFindings))
		for _, s := range e.SafeFindings {
			m[s.Key] = true
		}
		safe[e.ID] = m
	}

	var violations []Violation
	for _, af := range lockfile.NewFindingsByArtifact(locked, current, p.FailOnSeverity) {
		if ignored[af.RuleID] {
			continue
		}
		if safe[af.ArtifactID][lockfile.FindingKey(af.Finding)] {
			continue
		}
		violations = append(violations, Violation{
			Kind:     "finding",
			RuleID:   af.RuleID,
			Severity: af.Severity,
			Detail:   af.File,
		})
	}

	if p.RequireApproval {
		// Approval state is recorded in the lockfile (locked), not in the freshly
		// rebuilt current snapshot. An artifact passes only if it is present now
		// AND approved in the lockfile, matched by stable ID.
		approved := make(map[string]bool, len(locked.Artifacts))
		for _, e := range locked.Artifacts {
			if e.Approval != nil && e.Approval.Status == "approved" {
				approved[e.ID] = true
			}
		}
		for _, e := range current.Artifacts {
			if !approved[e.ID] {
				violations = append(violations, Violation{
					Kind: "unapproved",
					ID:   e.ID,
					Name: e.Name,
				})
			}
		}
	}

	// Remediation state (quarantine/freeze) is recorded in the lockfile and
	// always enforced, regardless of policy flags.
	present := make(map[string]bool, len(current.Artifacts))
	for _, e := range current.Artifacts {
		present[e.ID] = true
	}
	classes := lockfile.Classify(locked, current)
	for _, e := range locked.Artifacts {
		if e.Quarantined && present[e.ID] {
			violations = append(violations, Violation{
				Kind: "quarantined", ID: e.ID, Name: e.Name,
			})
		}
		if e.Frozen {
			switch classes[e.ID] {
			case lockfile.DriftClassUpdated, lockfile.DriftClassMutated, lockfile.DriftClassBroken:
				violations = append(violations, Violation{
					Kind: "frozen_drift", ID: e.ID, Name: e.Name, Detail: string(classes[e.ID]),
				})
			}
		}
	}

	// Allow/block lists, applied to the current snapshot.
	for _, e := range current.Artifacts {
		violations = append(violations, p.ListViolations(e.ID, e.Name, e.Source.Ref)...)
	}

	return Result{Violations: violations}
}

// ListViolations applies the publisher/artifact allow and block lists to a
// single artifact's name and source ref, returning any matches. It is the one
// home for that matching so the verify gate (Evaluate) and the fleet
// conformance check share identical semantics. Pure: no lockfile needed.
func (p Policy) ListViolations(id, name, sourceRef string) []Violation {
	src := strings.ToLower(sourceRef)
	lname := strings.ToLower(name)
	var out []Violation
	if m, ok := containsAny(src, p.BlockPublishers); ok {
		out = append(out, Violation{Kind: "blocked_publisher", ID: id, Name: name, Detail: m})
	}
	if m, ok := containsAny(lname, p.BlockArtifacts); ok {
		out = append(out, Violation{Kind: "blocked_artifact", ID: id, Name: name, Detail: m})
	}
	if len(p.AllowPublishers) > 0 {
		if _, ok := containsAny(src, p.AllowPublishers); !ok {
			out = append(out, Violation{Kind: "not_allowlisted", ID: id, Name: name})
		}
	}
	return out
}
