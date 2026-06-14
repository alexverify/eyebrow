package resolve

import (
	"context"
	"errors"
	"testing"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/platform/run"
)

func TestParseGitRef(t *testing.T) {
	cases := []struct{ ref, url, gitRef string }{
		{"git+https://github.com/a/b#main", "https://github.com/a/b", "main"},
		{"https://github.com/a/b#v1.0.0", "https://github.com/a/b", "v1.0.0"},
		{"https://github.com/a/b", "https://github.com/a/b", "HEAD"},
	}
	for _, c := range cases {
		url, gitRef := parseGitRef(c.ref)
		if url != c.url || gitRef != c.gitRef {
			t.Errorf("parseGitRef(%q) = (%q,%q), want (%q,%q)", c.ref, url, gitRef, c.url, c.gitRef)
		}
	}
}

func TestGitResolvePinsSHA(t *testing.T) {
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"git ls-remote https://github.com/a/b main": {Out: []byte(sha + "\trefs/heads/main\n")},
	}}
	g := Git{Runner: runner}
	res, err := g.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceGit, Ref: "git+https://github.com/a/b#main"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.PinnedRef != "https://github.com/a/b#"+sha {
		t.Errorf("PinnedRef = %q", res.PinnedRef)
	}
	if !hasRule(res.Warnings, "UNPINNED-GIT") {
		t.Error("a branch ref should be flagged UNPINNED-GIT")
	}
}

func TestGitResolveAcceptsExplicitSHA(t *testing.T) {
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"git ls-remote https://github.com/a/b " + sha: {Out: []byte(sha + "\trefs/heads/main\n")},
	}}
	g := Git{Runner: runner}
	res, err := g.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceGit, Ref: "https://github.com/a/b#" + sha})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if hasRule(res.Warnings, "UNPINNED-GIT") {
		t.Error("an explicit SHA must not be flagged unpinned")
	}
	if res.PinnedRef != "https://github.com/a/b#"+sha {
		t.Errorf("PinnedRef = %q", res.PinnedRef)
	}
}

func TestGitResolveRecordsSignedCommitProvenance(t *testing.T) {
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"git ls-remote https://github.com/a/b " + sha: {Out: []byte(sha + "\trefs/heads/main\n")},
		"git verify-commit " + sha:                    {}, // exit zero => valid signature
	}}
	g := Git{Runner: runner}
	res, err := g.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceGit, Ref: "https://github.com/a/b#" + sha})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Provenance == "" {
		t.Error("a verified commit signature should record provenance")
	}
}

func TestGitResolveUnsignedCommitHasNoProvenance(t *testing.T) {
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"git ls-remote https://github.com/a/b " + sha: {Out: []byte(sha + "\trefs/heads/main\n")},
		"git verify-commit " + sha:                    {Err: errors.New("error: no signature found")},
	}}
	g := Git{Runner: runner}
	res, err := g.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceGit, Ref: "https://github.com/a/b#" + sha})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Provenance != "" {
		t.Errorf("an unsigned commit must not record provenance, got %q", res.Provenance)
	}
}
