package engine_test

import (
	"testing"

	"github.com/alexverify/eyebrow/pkg/engine"
)

// Every finding the pipeline can raise must be in the public rule list, or an
// embedder sees a rule id in a report that Rules() and RuleCount never named.
func TestRulesListsEveryPipelineRule(t *testing.T) {
	want := map[string]string{
		"LOCAL-OUTSIDE-ROOT":   "high",
		"SKILLS-LOCK-MISMATCH": "high",
		"RESOLVE-UNSUPPORTED":  "medium",
		"RESOLVE-FAILED":       "high",
	}
	for _, r := range engine.Rules() {
		if sev, ok := want[r.ID]; ok {
			if r.Severity != sev {
				t.Errorf("rule %s severity %q, want %q", r.ID, r.Severity, sev)
			}
			delete(want, r.ID)
		}
	}
	for id := range want {
		t.Errorf("%s missing from Rules()", id)
	}
}
