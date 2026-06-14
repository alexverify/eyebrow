// Package policy defines the rules a team can enforce over an inventory, and
// the pure evaluation that turns a locked + current snapshot into a pass/fail
// decision. It is part of the domain core: no IO. Loading the policy file lives
// in the policystore adapter.
package policy

import (
	"strings"

	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/domain/lockfile"
)

// Policy is the team-configurable gate applied by `verify --ci`.
type Policy struct {
	// FailOnSeverity is the lowest severity of a newly introduced finding that
	// fails the gate (default: high).
	FailOnSeverity finding.Severity `json:"failOnSeverity,omitempty"`
	// IgnoreRules suppresses specific rule IDs (accepted false positives).
	IgnoreRules []string `json:"ignoreRules,omitempty"`
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

	ignored := make(map[string]bool, len(p.IgnoreRules))
	for _, r := range p.IgnoreRules {
		ignored[r] = true
	}

	var violations []Violation
	for _, f := range lockfile.NewFindings(locked, current, p.FailOnSeverity) {
		if ignored[f.RuleID] {
			continue
		}
		violations = append(violations, Violation{
			Kind:     "finding",
			RuleID:   f.RuleID,
			Severity: f.Severity,
			Detail:   f.File,
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
		src := strings.ToLower(e.Source.Ref)
		name := strings.ToLower(e.Name)
		if m, ok := containsAny(src, p.BlockPublishers); ok {
			violations = append(violations, Violation{Kind: "blocked_publisher", ID: e.ID, Name: e.Name, Detail: m})
		}
		if m, ok := containsAny(name, p.BlockArtifacts); ok {
			violations = append(violations, Violation{Kind: "blocked_artifact", ID: e.ID, Name: e.Name, Detail: m})
		}
		if len(p.AllowPublishers) > 0 {
			if _, ok := containsAny(src, p.AllowPublishers); !ok {
				violations = append(violations, Violation{Kind: "not_allowlisted", ID: e.ID, Name: e.Name})
			}
		}
	}

	return Result{Violations: violations}
}
