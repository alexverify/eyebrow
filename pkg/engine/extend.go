package engine

import (
	"context"
	"fmt"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// Analyzer is an extra static analyzer. Analyze receives an artifact and the
// directory holding its resolved files, and returns the findings it adds.
// Extra analyzers see artifact directories only, never inline content: an
// artifact whose source is inline (a hook or rules file carried as literal
// text rather than a file on disk) is not passed to Analyze at all, since
// there is no directory to hand it.
type Analyzer interface {
	Analyze(ctx context.Context, a Artifact, root string) ([]Finding, error)
}

// Discoverer is an extra layout reader. Discover receives a project root and
// returns the artifacts it finds there.
type Discoverer interface {
	Discover(ctx context.Context, root string) ([]Discovered, error)
}

// Discovered is what an extra Discoverer reports for one artifact. The engine
// assigns the ID and scope.
type Discovered struct {
	Tool           string // e.g. "ai17z"
	Type           string // one of the artifact types: skill, mcp_server, plugin, subagent, hook, rules, context
	Name           string
	SourceKind     string // "local" with SourceRef a directory or file path is the common case
	SourceRef      string
	DiscoveredFrom string // the config or manifest file the artifact came from
}

type analyzerAdapter struct{ a Analyzer }

// Analyze maps the domain artifact to the public shape, runs the extra
// analyzer on the resolved directory, and maps its findings back.
func (ad analyzerAdapter) Analyze(ctx context.Context, a artifact.Artifact, root string) ([]finding.Finding, error) {
	pub := Artifact{
		ID: a.ID, Tool: a.Tool, Scope: a.Scope, Type: string(a.Type), Name: a.Name,
		SourceKind: string(a.Source.Kind), SourceRef: a.Source.Ref, Digest: a.ContentHash,
	}
	fs, err := ad.a.Analyze(ctx, pub, root)
	if err != nil {
		return nil, fmt.Errorf("extra analyzer: %w", err)
	}
	out := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		sev := finding.Severity(f.Severity)
		if !isKnownSeverity(sev) {
			return nil, fmt.Errorf("extra analyzer: rule %q: unknown severity %q", f.RuleID, f.Severity)
		}
		out = append(out, finding.Finding{
			RuleID: f.RuleID, Severity: sev, OWASP: f.Category,
			File: f.File, Line: f.Line, Snippet: f.Snippet, Explanation: f.Explanation,
		})
	}
	return out, nil
}

// isKnownSeverity reports whether sev is one of the five severities the
// domain model defines.
func isKnownSeverity(sev finding.Severity) bool {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo:
		return true
	default:
		return false
	}
}

// AnalyzeContent is a no-op: extra analyzers see directories only.
func (analyzerAdapter) AnalyzeContent(context.Context, artifact.Artifact, []byte) ([]finding.Finding, error) {
	return nil, nil
}

type discovererAdapter struct{ d Discoverer }

// Discover runs the extra discoverer once per project scope and stamps the
// engine-owned fields: scope string and stable ID.
func (dd discovererAdapter) Discover(ctx context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" {
			continue
		}
		found, err := dd.d.Discover(ctx, sc.Path)
		if err != nil {
			return nil, fmt.Errorf("extra discoverer: %w", err)
		}
		for _, f := range found {
			if !artifact.IsType(f.Type) {
				return nil, fmt.Errorf("extra discoverer: unknown artifact type %q for %q", f.Type, f.Name)
			}
			if f.Tool == "" || f.Name == "" {
				return nil, fmt.Errorf("extra discoverer: tool and name are required (got %+v)", f)
			}
			scope := sc.String()
			out = append(out, artifact.Artifact{
				ID:             artifact.MakeID(f.Tool, scope, artifact.Type(f.Type), f.Name),
				Tool:           f.Tool,
				Scope:          scope,
				Type:           artifact.Type(f.Type),
				Name:           f.Name,
				Source:         artifact.Source{Kind: artifact.SourceKind(f.SourceKind), Ref: f.SourceRef},
				DiscoveredFrom: f.DiscoveredFrom,
			})
		}
	}
	return out, nil
}
