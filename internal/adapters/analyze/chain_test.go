package analyze

import (
	"context"
	"errors"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// fakeAnalyzer returns fixed findings and an error from both methods.
type fakeAnalyzer struct {
	findings []finding.Finding
	err      error
}

func (f fakeAnalyzer) Analyze(context.Context, artifact.Artifact, string) ([]finding.Finding, error) {
	return f.findings, f.err
}

func (f fakeAnalyzer) AnalyzeContent(context.Context, artifact.Artifact, []byte) ([]finding.Finding, error) {
	return f.findings, f.err
}

func TestChainConcatenatesFindings(t *testing.T) {
	c := NewChain(
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "A"}}},
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "B"}, {RuleID: "C"}}},
	)
	got, err := c.Analyze(context.Background(), artifact.Artifact{}, "/root")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("findings = %d, want 3", len(got))
	}
	if got[0].RuleID != "A" || got[1].RuleID != "B" || got[2].RuleID != "C" {
		t.Errorf("findings not concatenated in order: %+v", got)
	}
}

func TestChainSkipsNotImplemented(t *testing.T) {
	c := NewChain(
		fakeAnalyzer{err: ports.ErrNotImplemented},
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "B"}}},
	)
	got, err := c.Analyze(context.Background(), artifact.Artifact{}, "/root")
	if err != nil {
		t.Fatalf("ErrNotImplemented should be skipped, got %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "B" {
		t.Errorf("expected only the implemented analyzer's finding, got %+v", got)
	}
}

func TestChainPropagatesRealError(t *testing.T) {
	boom := errors.New("boom")
	c := NewChain(
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "A"}}},
		fakeAnalyzer{err: boom},
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "never"}}},
	)
	got, err := c.Analyze(context.Background(), artifact.Artifact{}, "/root")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	// findings accumulated before the failure are returned alongside the error.
	if len(got) != 1 || got[0].RuleID != "A" {
		t.Errorf("partial findings = %+v, want [A]", got)
	}
}

func TestChainContentMirrorsAnalyze(t *testing.T) {
	c := NewChain(
		fakeAnalyzer{err: ports.ErrNotImplemented},
		fakeAnalyzer{findings: []finding.Finding{{RuleID: "X"}}},
	)
	got, err := c.AnalyzeContent(context.Background(), artifact.Artifact{}, []byte("blob"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "X" {
		t.Errorf("AnalyzeContent = %+v, want [X]", got)
	}

	boom := errors.New("boom")
	c2 := NewChain(fakeAnalyzer{err: boom})
	if _, err := c2.AnalyzeContent(context.Background(), artifact.Artifact{}, nil); !errors.Is(err, boom) {
		t.Errorf("AnalyzeContent err = %v, want boom", err)
	}
}

func TestChainEmpty(t *testing.T) {
	c := NewChain()
	got, err := c.Analyze(context.Background(), artifact.Artifact{}, "/root")
	if err != nil || got != nil {
		t.Errorf("empty chain = (%v, %v), want (nil, nil)", got, err)
	}
}
