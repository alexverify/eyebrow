package resolve

import (
	"context"
	"errors"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/platform/run"
)

// stubFetcher lets npm tests bypass the real npm-pack download.
type stubFetcher struct {
	dir string
	err error
}

func (s stubFetcher) fetch(context.Context, string) (string, error) { return s.dir, s.err }

func npmRunner() *run.Fake {
	return &run.Fake{Responses: map[string]run.FakeResponse{
		"npm view some-mcp@1.4.2 version --json":        {Out: []byte(`"1.4.2"`)},
		"npm view some-mcp@1.4.2 dist.integrity --json": {Out: []byte(`"sha512-abc"`)},
		"npm view some-mcp@latest version --json":       {Out: []byte(`"1.4.2"`)},
	}}
}

func TestNPMResolveCapturesProvenance(t *testing.T) {
	r := npmRunner()
	r.Responses["npm view some-mcp@1.4.2 dist.attestations.provenance.predicateType --json"] =
		run.FakeResponse{Out: []byte(`"https://slsa.dev/provenance/v1"`)}
	n := NPM{Runner: r, Fetcher: stubFetcher{dir: "/tmp/extracted"}}
	res, err := n.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceNPM, Ref: "some-mcp@1.4.2"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Provenance != "https://slsa.dev/provenance/v1" {
		t.Fatalf("Provenance = %q, want the SLSA predicate type", res.Provenance)
	}
}

func TestNPMResolveNoProvenanceWhenAbsent(t *testing.T) {
	// npmRunner() has no attestations response → the lookup errors and degrades.
	n := NPM{Runner: npmRunner(), Fetcher: stubFetcher{dir: "/tmp/x"}}
	res, err := n.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceNPM, Ref: "some-mcp@1.4.2"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Provenance != "" {
		t.Errorf("Provenance should be empty when the package has no attestation, got %q", res.Provenance)
	}
}

func TestNPMResolvePinsExactVersionAndIntegrity(t *testing.T) {
	n := NPM{Runner: npmRunner(), Fetcher: stubFetcher{dir: "/tmp/extracted"}}
	res, err := n.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceNPM, Ref: "some-mcp@1.4.2"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.PinnedRef != "some-mcp@1.4.2" {
		t.Errorf("PinnedRef = %q", res.PinnedRef)
	}
	if res.Integrity != "sha512-abc" {
		t.Errorf("Integrity = %q", res.Integrity)
	}
	if res.LocalPath != "/tmp/extracted" {
		t.Errorf("LocalPath = %q", res.LocalPath)
	}
	if hasRule(res.Warnings, "UNPINNED-NPM") {
		t.Error("exact version must not be flagged as unpinned")
	}
}

func TestNPMResolveFlagsUnpinned(t *testing.T) {
	n := NPM{Runner: npmRunner(), Fetcher: stubFetcher{dir: "/tmp/x"}}
	res, err := n.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceNPM, Ref: "some-mcp@latest"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !hasRule(res.Warnings, "UNPINNED-NPM") {
		t.Fatalf("expected UNPINNED-NPM warning, got %+v", res.Warnings)
	}
	if res.PinnedRef != "some-mcp@1.4.2" {
		t.Errorf("unpinned spec should still resolve to a concrete version, got %q", res.PinnedRef)
	}
}

func TestNPMResolveDegradesWhenFetchFails(t *testing.T) {
	n := NPM{Runner: npmRunner(), Fetcher: stubFetcher{err: errors.New("network down")}}
	res, err := n.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceNPM, Ref: "some-mcp@1.4.2"})
	if err != nil {
		t.Fatalf("Resolve must not hard-fail on fetch error: %v", err)
	}
	if res.LocalPath != "" {
		t.Errorf("LocalPath should be empty when fetch fails, got %q", res.LocalPath)
	}
	if !hasRule(res.Warnings, "NPM-FETCH-FAILED") {
		t.Errorf("expected NPM-FETCH-FAILED warning, got %+v", res.Warnings)
	}
	// Pinning still succeeds even if code couldn't be downloaded.
	if res.PinnedRef == "" || res.Integrity == "" {
		t.Errorf("pinning should still succeed: ref=%q integrity=%q", res.PinnedRef, res.Integrity)
	}
}

func hasRule(fs []finding.Finding, rule string) bool {
	for _, f := range fs {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}
