package finding

import (
	"errors"
	"strings"
	"testing"
)

// Findings the pipeline raises without a pattern match live here so their ids
// are reserved in one place and rule tables can list them. Each constructor
// carries the specific detail; the template in PipelineRules carries a generic
// explanation a rule table can print.
func TestSkillsLockMismatchCarriesBothHashes(t *testing.T) {
	f := SkillsLockMismatch("aaaa", "bbbb")
	if RuleSkillsLockMismatch != "SKILLS-LOCK-MISMATCH" {
		t.Errorf("RuleSkillsLockMismatch = %q", RuleSkillsLockMismatch)
	}
	if f.RuleID != RuleSkillsLockMismatch {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityHigh || f.OWASP != "ASK-02" || f.File != "skills-lock.json" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, "aaaa") || !strings.Contains(f.Explanation, "bbbb") {
		t.Errorf("explanation must name recorded and actual hashes: %q", f.Explanation)
	}
}

func TestResolveUnsupportedNamesTheSourceKind(t *testing.T) {
	f := ResolveUnsupported("container")
	if RuleResolveUnsupported != "RESOLVE-UNSUPPORTED" {
		t.Errorf("RuleResolveUnsupported = %q", RuleResolveUnsupported)
	}
	if f.RuleID != RuleResolveUnsupported {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityMedium || f.OWASP != "ASK-02" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, `"container"`) {
		t.Errorf("explanation must name the kind: %q", f.Explanation)
	}
}

func TestResolveFailedCarriesTheError(t *testing.T) {
	f := ResolveFailed(errors.New("dns lookup failed"))
	if RuleResolveFailed != "RESOLVE-FAILED" {
		t.Errorf("RuleResolveFailed = %q", RuleResolveFailed)
	}
	if f.RuleID != RuleResolveFailed {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityHigh || f.OWASP != "ASK-02" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, "dns lookup failed") {
		t.Errorf("explanation must carry the error: %q", f.Explanation)
	}
}

// PipelineRules is the registry rule tables read. Every pipeline rule id
// appears exactly once, with every field a table needs filled in, and the
// generic explanation must not leak a placeholder from the constructor.
func TestPipelineRulesListsEveryPipelineRuleOnce(t *testing.T) {
	want := map[string]Severity{
		RuleLocalOutsideRoot:           SeverityHigh,
		RuleSkillsLockMismatch:         SeverityHigh,
		RuleClawHubFingerprintMismatch: SeverityHigh,
		RuleResolveUnsupported:         SeverityMedium,
		RuleResolveFailed:              SeverityHigh,
	}
	got := PipelineRules()
	if len(got) != len(want) {
		t.Fatalf("PipelineRules has %d entries, want %d: %+v", len(got), len(want), got)
	}
	seen := map[string]bool{}
	for _, f := range got {
		sev, ok := want[f.RuleID]
		if !ok || seen[f.RuleID] {
			t.Fatalf("unexpected or duplicate rule %q", f.RuleID)
		}
		seen[f.RuleID] = true
		if f.Severity != sev || f.OWASP == "" || f.Explanation == "" {
			t.Errorf("rule %s incomplete: %+v", f.RuleID, f)
		}
		if strings.Contains(f.Explanation, "%") || strings.Contains(f.Explanation, `""`) {
			t.Errorf("rule %s explanation leaks a placeholder: %q", f.RuleID, f.Explanation)
		}
	}
}
