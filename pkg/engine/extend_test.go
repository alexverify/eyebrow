package engine_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/pkg/engine"
)

type wordAnalyzer struct{ word string }

func (w wordAnalyzer) Analyze(_ context.Context, _ engine.Artifact, root string) ([]engine.Finding, error) {
	b, err := os.ReadFile(filepath.Join(root, "SKILL.md"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // not a skill directory; nothing to say
	}
	if err != nil {
		return nil, err
	}
	if !containsWord(string(b), w.word) {
		return nil, nil
	}
	return []engine.Finding{{RuleID: "PRIVATE-WORD", Severity: "high", Category: "ASK-05",
		File: "SKILL.md", Line: 1, Explanation: "mentions " + w.word}}, nil
}

func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] == w {
			return true
		}
	}
	return false
}

func TestExtraAnalyzerFindingsAreReported(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock, Analyzers: []engine.Analyzer{wordAnalyzer{"deploy"}}})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, f := range rep.Findings {
		if f.RuleID == "PRIVATE-WORD" && f.Artifact == "deploy-helper" && f.Severity == "high" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("extra analyzer finding missing: %+v", rep.Findings)
	}
	if rep.Verdict != "fail" {
		t.Fatal("a high finding from an extra analyzer must fail the default policy")
	}
}

type folderDiscoverer struct{}

func (folderDiscoverer) Discover(_ context.Context, root string) ([]engine.Discovered, error) {
	dir := filepath.Join(root, "personas")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []engine.Discovered
	for _, en := range entries {
		if en.IsDir() {
			out = append(out, engine.Discovered{
				Tool: "persona-runtime", Type: "subagent", Name: en.Name(),
				SourceKind: "local", SourceRef: filepath.Join(dir, en.Name()),
				DiscoveredFrom: dir,
			})
		}
	}
	return out, nil
}

func TestExtraDiscovererArtifactsAreHashed(t *testing.T) {
	root := writeFixture(t, false)
	p := filepath.Join(root, "personas", "night-owl")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "persona.json"), []byte(`{"name":"night-owl"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.Options{Clock: fixedClock, Discoverers: []engine.Discoverer{folderDiscoverer{}}})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	var found *engine.Artifact
	for i := range rep.Artifacts {
		if rep.Artifacts[i].Tool == "persona-runtime" {
			found = &rep.Artifacts[i]
		}
	}
	if found == nil {
		t.Fatalf("extra discoverer artifact missing: %+v", rep.Artifacts)
	}
	if found.Type != "subagent" || found.Name != "night-owl" || found.Digest == "" || found.ID == "" {
		t.Fatalf("incomplete artifact %+v", *found)
	}
	if found.Scope != "project:"+root {
		t.Fatalf("scope %q, want project:%s", found.Scope, root)
	}
}

type badTypeDiscoverer struct{}

func (badTypeDiscoverer) Discover(context.Context, string) ([]engine.Discovered, error) {
	return []engine.Discovered{{Tool: "x", Type: "widget", Name: "n", SourceKind: "local", SourceRef: "."}}, nil
}

func TestExtraDiscovererRejectsUnknownType(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Discoverers: []engine.Discoverer{badTypeDiscoverer{}}})
	_, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err == nil {
		t.Fatal("expected an error for an unknown artifact type")
	}
}

type badSeverityAnalyzer struct{}

func (badSeverityAnalyzer) Analyze(_ context.Context, _ engine.Artifact, _ string) ([]engine.Finding, error) {
	return []engine.Finding{{RuleID: "BAD-SEV", Severity: "HIGH"}}, nil
}

func TestExtraAnalyzerRejectsUnknownSeverity(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock, Analyzers: []engine.Analyzer{badSeverityAnalyzer{}}})
	_, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err == nil {
		t.Fatal("expected an error for an unknown severity")
	}
}
