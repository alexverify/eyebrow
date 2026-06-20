package analyze

import (
	"context"
	"errors"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// Chain runs several analyzers in sequence and concatenates their findings.
// An analyzer reporting ports.ErrNotImplemented is skipped rather than failing
// the scan, so optional accelerators can be added without risk.
type Chain struct {
	analyzers []ports.Analyzer
}

// NewChain composes analyzers (e.g. native matchers + semgrep).
func NewChain(analyzers ...ports.Analyzer) *Chain {
	return &Chain{analyzers: analyzers}
}

// Analyze satisfies ports.Analyzer.
func (c *Chain) Analyze(ctx context.Context, a artifact.Artifact, root string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, an := range c.analyzers {
		fs, err := an.Analyze(ctx, a, root)
		if err != nil {
			if errors.Is(err, ports.ErrNotImplemented) {
				continue
			}
			return out, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

// AnalyzeContent satisfies ports.Analyzer for in-memory blobs.
func (c *Chain) AnalyzeContent(ctx context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, an := range c.analyzers {
		fs, err := an.AnalyzeContent(ctx, a, content)
		if err != nil {
			if errors.Is(err, ports.ErrNotImplemented) {
				continue
			}
			return out, err
		}
		out = append(out, fs...)
	}
	return out, nil
}
