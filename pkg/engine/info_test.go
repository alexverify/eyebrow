package engine_test

import (
	"sort"
	"testing"

	"github.com/alexverify/eyebrow/pkg/engine"
)

func TestRulesListsThePipeExecRule(t *testing.T) {
	rules := engine.Rules()
	if len(rules) == 0 {
		t.Fatal("no rules")
	}
	for _, r := range rules {
		if r.ID == "RCE-PIPE-EXEC" {
			if r.Severity != "critical" || r.Category != "ASK-01" || r.Explanation == "" {
				t.Fatalf("unexpected rule %+v", r)
			}
			return
		}
	}
	t.Fatal("RCE-PIPE-EXEC missing")
}

func TestVersionDescribesTheEngine(t *testing.T) {
	info := engine.Version()
	if info.Version == "" {
		t.Fatal("version empty")
	}
	if info.RuleCount != len(engine.Rules()) {
		t.Fatalf("rule count %d, rules %d", info.RuleCount, len(engine.Rules()))
	}
	if !sort.StringsAreSorted(info.SourceKinds) || !sort.StringsAreSorted(info.Tools) {
		t.Fatalf("lists must be sorted: %v %v", info.SourceKinds, info.Tools)
	}
	want := map[string]bool{"git": false, "npm": false, "local": false, "inline": false, "url": false}
	for _, k := range info.SourceKinds {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("source kind %q missing from %v", k, info.SourceKinds)
		}
	}
	found := false
	for _, tool := range info.Tools {
		if tool == "claude-code" {
			found = true
		}
	}
	if !found {
		t.Fatalf("claude-code missing from %v", info.Tools)
	}
}
