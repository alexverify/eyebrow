package engine

import (
	"context"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// Analyzer is an extra static analyzer. Analyze receives an artifact and the
// directory holding its resolved files, and returns the findings it adds.
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

func (analyzerAdapter) Analyze(context.Context, artifact.Artifact, string) ([]finding.Finding, error) {
	return nil, nil
}

func (analyzerAdapter) AnalyzeContent(context.Context, artifact.Artifact, []byte) ([]finding.Finding, error) {
	return nil, nil
}

type discovererAdapter struct{ d Discoverer }

func (discovererAdapter) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	return nil, nil
}
