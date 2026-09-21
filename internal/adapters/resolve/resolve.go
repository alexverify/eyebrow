// Package resolve turns a Source declaration into concrete, pinned,
// content-addressable code (or an integrity anchor for sources that cannot be
// hashed locally). A Router dispatches by source kind to per-kind resolvers:
// local, inline, npm, git, and url.
package resolve

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
	"github.com/alexverify/eyebrow/internal/platform/run"
)

// Router dispatches resolution by Source.Kind.
type Router struct {
	resolvers map[artifact.SourceKind]ports.Resolver
}

// RouterOptions configure NewRouterWith.
type RouterOptions struct {
	// DialContext, when set, opens every TCP connection the router's
	// resolvers make themselves: the url resolver's TLS probe and the
	// registry resolver's HTTP fetch (and its own TLS probe of the
	// distribution host). Child processes such as git and npm are not
	// affected. Nil keeps the standard library's default dialer, exactly
	// like NewRouter.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewRouter wires the default per-kind resolvers.
func NewRouter() *Router {
	return NewRouterWith(RouterOptions{})
}

// NewRouterWith wires the default per-kind resolvers, threading opts.DialContext
// into every resolver that opens a network connection itself.
func NewRouterWith(opts RouterOptions) *Router {
	runner := run.OS{}
	return &Router{resolvers: map[artifact.SourceKind]ports.Resolver{
		artifact.SourceLocal:     Local{},
		artifact.SourceInline:    Inline{},
		artifact.SourceNPM:       NewNPM(runner),
		artifact.SourceGit:       NewGit(runner),
		artifact.SourceURL:       NewURL(TLSCertFetcher{DialContext: opts.DialContext}),
		artifact.SourceContainer: NewContainer(runner),
		artifact.SourceRegistry:  NewRegistryWith(opts.DialContext),
	}}
}

// NewOfflineRouter wires only the resolvers that never shell out or make a
// network request: Local and Inline. Every other source kind degrades to the
// router's usual ErrUnsupported (recorded as a finding, not a failure) instead
// of running git, npm, or a fetch.
func NewOfflineRouter() *Router {
	return &Router{resolvers: map[artifact.SourceKind]ports.Resolver{
		artifact.SourceLocal:  Local{},
		artifact.SourceInline: Inline{},
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
	// LocalPath is absolute so the hasher can read files regardless of cwd, but
	// PinnedRef keeps the ref exactly as discovered. A committed lockfile is
	// compared across machines (dev vs CI); absolutizing the ref here would make
	// every local artifact read as version_changed drift when the checkout lives
	// at a different path. Scanned with a relative --path, the ref stays relative
	// and portable; an already-absolute ref is preserved as-is.
	return ports.Resolution{LocalPath: abs, PinnedRef: path}, nil
}

// Inline content-addresses literal text (hooks, rules, context). By convention
// the literal content is carried in Source.Ref.
type Inline struct{}

// Resolve satisfies ports.Resolver.
func (Inline) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	return ports.Resolution{ContentHash: digest.Inline([]byte(src.Ref))}, nil
}
