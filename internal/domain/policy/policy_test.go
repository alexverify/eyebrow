package policy

import (
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

func entry(name string, approved bool, fs ...finding.Finding) lockfile.Entry {
	a := artifact.Artifact{
		ID:       artifact.MakeID("claude-code", "global", artifact.TypeSkill, name),
		Tool:     "claude-code",
		Scope:    "global",
		Type:     artifact.TypeSkill,
		Name:     name,
		Findings: fs,
	}
	e := lockfile.Entry{Artifact: a}
	if approved {
		e.Approval = &lockfile.Approval{Status: "approved", By: "me", At: time.Unix(0, 0).UTC()}
	}
	return e
}

func lf(entries ...lockfile.Entry) lockfile.Lockfile {
	return lockfile.Lockfile{Version: lockfile.Version, Artifacts: entries}
}

func TestEvaluateFlagsNewFindingOverThreshold(t *testing.T) {
	locked := lf(entry("a", false))
	current := lf(entry("a", false, finding.Finding{RuleID: "RCE", Severity: finding.SeverityCritical, File: "x.sh"}))

	res := Evaluate(Default(), locked, current)
	if res.OK() {
		t.Fatal("a new critical finding must violate the default policy")
	}
	if res.Violations[0].Kind != "finding" || res.Violations[0].RuleID != "RCE" {
		t.Fatalf("unexpected violation: %+v", res.Violations[0])
	}
}

func TestEvaluateIgnoresSuppressedRule(t *testing.T) {
	locked := lf(entry("a", false))
	current := lf(entry("a", false, finding.Finding{RuleID: "EXEC-PRIMITIVE", Severity: finding.SeverityHigh}))

	p := Policy{FailOnSeverity: finding.SeverityHigh, IgnoreRules: []string{"EXEC-PRIMITIVE"}}
	if !Evaluate(p, locked, current).OK() {
		t.Fatal("ignored rule should not produce a violation")
	}
}

func TestEvaluateRespectsThreshold(t *testing.T) {
	locked := lf(entry("a", false))
	current := lf(entry("a", false, finding.Finding{RuleID: "NOTE", Severity: finding.SeverityMedium}))

	// Default threshold is high, so a medium finding does not gate.
	if !Evaluate(Default(), locked, current).OK() {
		t.Fatal("medium finding should pass a high threshold")
	}
	// Lowering the threshold to medium should now gate.
	if Evaluate(Policy{FailOnSeverity: finding.SeverityMedium}, locked, current).OK() {
		t.Fatal("medium finding should fail a medium threshold")
	}
}

func TestEvaluateRequireApproval(t *testing.T) {
	// Approval lives in the lockfile (locked); current is rebuilt without it.
	locked := lf(entry("a", false), entry("b", true))
	current := lf(entry("a", false), entry("b", false))
	p := Policy{RequireApproval: true}

	res := Evaluate(p, locked, current)
	if res.OK() {
		t.Fatal("an unapproved artifact must violate requireApproval")
	}
	gotUnapproved := 0
	for _, v := range res.Violations {
		if v.Kind == "unapproved" {
			gotUnapproved++
			if v.Name != "a" {
				t.Errorf("only 'a' is unapproved, got %q", v.Name)
			}
		}
	}
	if gotUnapproved != 1 {
		t.Fatalf("want 1 unapproved violation, got %d: %+v", gotUnapproved, res.Violations)
	}
}
