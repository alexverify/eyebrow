// Package resolve turns a Source declaration into concrete, pinned,
// content-addressable code (or an integrity anchor for sources that cannot be
// hashed locally). A Router dispatches by source kind to per-kind resolvers:
// local, inline, npm, git, and url.
package resolve

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/digest"
	"github.com/alexverify/agentguard/internal/platform/run"
)

// Router dispatches resolution by Source.Kind.
type Router struct {
	resolvers map[artifact.SourceKind]ports.Resolver
}

// NewRouter wires the default per-kind resolvers.
func NewRouter() *Router {
	runner := run.OS{}
	return &Router{resolvers: map[artifact.SourceKind]ports.Resolver{
		artifact.SourceLocal:  Local{},
		artifact.SourceInline: Inline{},
		artifact.SourceNPM:    NewNPM(runner),
		artifact.SourceGit:    NewGit(runner),
		artifact.SourceURL:    NewURL(TLSCertFetcher{}),
	}}
}

// Resolve satisfies ports.Resolver by delegating to the per-kind resolver.
func (r *Router) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	res, ok := r.resolvers[src.Kind]
	if !ok {
		return ports.Resolution{}, ports.ErrUnsupported
	}
	return res.Resolve(ctx, src)
}

// Local resolves a filesystem path to an absolute, hashable location.
type Local struct{}

// Resolve satisfies ports.Resolver.
func (Local) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	path := src.Ref
	if path == "" {
		path = src.Command
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ports.Resolution{}, err
	}
	if _, err := os.Stat(abs); err != nil {
		return ports.Resolution{}, fmt.Errorf("local source %q: %w", abs, err)
	}
	return ports.Resolution{LocalPath: abs, PinnedRef: abs}, nil
}

// Inline content-addresses literal text (hooks, rules, context). By convention
// the literal content is carried in Source.Ref.
type Inline struct{}

// Resolve satisfies ports.Resolver.
func (Inline) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	return ports.Resolution{ContentHash: digest.Inline([]byte(src.Ref))}, nil
}
