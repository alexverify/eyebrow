package engine

import (
	"sort"

	"github.com/alexverify/eyebrow/internal/adapters/analyze"
	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/buildinfo"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Rule describes one built-in static rule.
type Rule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"` // OWASP Agentic Skills Top 10 id
	Explanation string `json:"explanation"`
}

// Rules returns the native rule set in evaluation order.
func Rules() []Rule {
	table := analyze.RuleTable()
	out := make([]Rule, 0, len(table))
	for _, r := range table {
		out = append(out, Rule{ID: r.ID, Severity: string(r.Severity), Category: r.OWASP, Explanation: r.Explanation})
	}
	return out
}

// Info describes the engine build.
type Info struct {
	Version     string   `json:"version"`
	RuleCount   int      `json:"ruleCount"`
	SourceKinds []string `json:"sourceKinds"`
	Tools       []string `json:"tools"`
}

// Version reports the engine version, the rule count, the source kinds the
// resolver pins, and the tools discovery covers.
func Version() Info {
	kinds := []string{
		string(artifact.SourceNPM), string(artifact.SourceGit), string(artifact.SourceURL),
		string(artifact.SourceLocal), string(artifact.SourceInline), string(artifact.SourceContainer),
		string(artifact.SourceRegistry),
	}
	sort.Strings(kinds)
	return Info{
		Version:     buildinfo.Version,
		RuleCount:   len(analyze.RuleTable()),
		SourceKinds: kinds,
		Tools:       discover.Default().Tools(),
	}
}
