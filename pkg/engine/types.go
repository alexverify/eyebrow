package engine

import (
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// Artifact is one discovered add-on: a skill, MCP server, plugin, subagent,
// hook, rules file, or context file.
type Artifact struct {
	ID         string    `json:"id"`
	Tool       string    `json:"tool"`
	Scope      string    `json:"scope"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	SourceKind string    `json:"sourceKind"`
	SourceRef  string    `json:"sourceRef,omitempty"`
	Digest     string    `json:"digest,omitempty"` // canonical content hash
	Findings   []Finding `json:"findings,omitempty"`
}

// Finding is one static-analysis hit, flattened with the artifact name.
type Finding struct {
	Artifact    string `json:"artifact"`
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"` // OWASP Agentic Skills Top 10 id
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// Violation is one reason the policy gate failed.
type Violation struct {
	Kind     string `json:"kind"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// PolicyResult lists the violations; an empty list means the gate passed.
type PolicyResult struct {
	Violations []Violation `json:"violations"`
}

// Change is one drift between an approved lockfile and the current state.
type Change struct {
	Kind string `json:"kind"` // added | removed | content_changed | version_changed | integrity_changed | cert_rotated
	ID   string `json:"id"`
	Name string `json:"name"`
	Old  string `json:"old,omitempty"`
	New  string `json:"new,omitempty"`
}

func artifactsOf(lf lockfile.Lockfile) []Artifact {
	out := make([]Artifact, 0, len(lf.Artifacts))
	for _, e := range lf.Artifacts {
		out = append(out, Artifact{
			ID:         e.ID,
			Tool:       e.Tool,
			Scope:      e.Scope,
			Type:       string(e.Type),
			Name:       e.Name,
			SourceKind: string(e.Source.Kind),
			SourceRef:  e.Source.Ref,
			Digest:     e.ContentHash,
			Findings:   findingsOf(e.Name, e.Findings),
		})
	}
	return out
}

func findingsOf(artifactName string, fs []finding.Finding) []Finding {
	if len(fs) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, Finding{
			Artifact:    artifactName,
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Category:    f.OWASP,
			File:        f.File,
			Line:        f.Line,
			Snippet:     f.Snippet,
			Explanation: f.Explanation,
		})
	}
	return out
}

func allFindings(lf lockfile.Lockfile) []Finding {
	var out []Finding
	for _, e := range lf.Artifacts {
		out = append(out, findingsOf(e.Name, e.Findings)...)
	}
	return out
}

func policyResultOf(r policy.Result) PolicyResult {
	out := PolicyResult{Violations: []Violation{}}
	for _, v := range r.Violations {
		out.Violations = append(out.Violations, Violation{
			Kind: v.Kind, ID: v.ID, Name: v.Name, RuleID: v.RuleID,
			Severity: string(v.Severity), Detail: v.Detail,
		})
	}
	return out
}

func changesOf(d lockfile.Diff) []Change {
	out := make([]Change, 0, len(d.Changes))
	for _, c := range d.Changes {
		out = append(out, Change{Kind: string(c.Kind), ID: c.ID, Name: c.Name, Old: c.Old, New: c.New})
	}
	return out
}
