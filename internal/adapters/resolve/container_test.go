package resolve

import (
	"context"
	"errors"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/platform/run"
)

func TestContainerVerifiesSignedImage(t *testing.T) {
	const ref = "ghcr.io/foo/mcp@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"cosign verify " + ref: {Out: []byte("verified")},
	}}
	c := Container{Runner: runner}
	res, err := c.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceContainer, Ref: ref})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.PinnedRef != ref {
		t.Errorf("PinnedRef = %q, want %q", res.PinnedRef, ref)
	}
	if res.Provenance == "" {
		t.Error("a cosign-verified image should record provenance")
	}
	if hasRule(res.Warnings, "UNPINNED-CONTAINER") {
		t.Error("a digest-pinned image must not be flagged unpinned")
	}
	if hasRule(res.Warnings, "CONTAINER-UNSIGNED") {
		t.Error("a verified image must not be flagged unsigned")
	}
}

func TestContainerUnsignedImageDegrades(t *testing.T) {
	const ref = "docker.io/foo/mcp:latest"
	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"cosign verify " + ref: {Err: errors.New("no signatures found")},
	}}
	c := Container{Runner: runner}
	res, err := c.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceContainer, Ref: ref})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Provenance != "" {
		t.Errorf("an unsigned image must not record provenance, got %q", res.Provenance)
	}
	if !hasRule(res.Warnings, "UNPINNED-CONTAINER") {
		t.Error("a :tag image should be flagged UNPINNED-CONTAINER")
	}
	if !hasRule(res.Warnings, "CONTAINER-UNSIGNED") {
		t.Error("an unverified image should add the informational CONTAINER-UNSIGNED finding")
	}
}

func TestContainerEmptyRefErrors(t *testing.T) {
	c := Container{Runner: &run.Fake{}}
	if _, err := c.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceContainer}); err == nil {
		t.Error("an empty image reference should error")
	}
}
