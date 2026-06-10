// Package resolve turns a Source declaration into concrete, pinned,
// content-addressable code (or an integrity anchor for sources that cannot be
// hashed locally). A Router dispatches by source kind to per-kind resolvers.
//
// Implemented now: local directories/files and inline content — enough for an
// end-to-end scan of locally-installed artifacts. npm, git, and remote-url
// resolution are documented seams returning ports.ErrNotImplemented, which the
// scan service degrades into a finding rather than a hard failure.
package resolve

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentguard/agentguard/internal/app/ports"
	"github.com/agentguard/agentguard/internal/domain/artifact"
	"github.com/agentguard/agentguard/internal/domain/digest"
)

// Router dispatches resolution by Source.Kind.
type Router struct {
	resolvers map[artifact.SourceKind]ports.Resolver
}

// NewRouter wires the default per-kind resolvers.
func NewRouter() *Router {
	return &Router{resolvers: map[artifact.SourceKind]ports.Resolver{
		artifact.SourceLocal:  Local{},
		artifact.SourceInline: Inline{},
		artifact.SourceNPM:    notImplemented{artifact.SourceNPM},
		artifact.SourceGit:    notImplemented{artifact.SourceGit},
		artifact.SourceURL:    notImplemented{artifact.SourceURL},
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

// notImplemented is the shared stub for resolvers that are scaffolded but not
// yet built (npm, git, url). It reports the kind so logs are actionable.
type notImplemented struct{ kind artifact.SourceKind }

// Resolve satisfies ports.Resolver.
func (n notImplemented) Resolve(context.Context, artifact.Source) (ports.Resolution, error) {
	return ports.Resolution{}, fmt.Errorf("%s resolver: %w", n.kind, ports.ErrNotImplemented)
}
