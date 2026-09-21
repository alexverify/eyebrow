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
	"strings"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
	"github.com/alexverify/eyebrow/internal/domain/finding"
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
	// ConfineRoot, when set, confines local sources to this directory: a
	// local path that resolves outside it (after following symlinks) is
	// refused with a LOCAL-OUTSIDE-ROOT finding instead of being resolved,
	// so nothing downstream reads it. Empty leaves local sources unconfined.
	ConfineRoot string
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
		artifact.SourceLocal:     Local{Root: opts.ConfineRoot},
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
	return NewOfflineRouterWith(RouterOptions{})
}

// NewOfflineRouterWith is NewOfflineRouter with opts.ConfineRoot applied to
// the local resolver. DialContext is unused: an offline router never dials.
func NewOfflineRouterWith(opts RouterOptions) *Router {
	return &Router{resolvers: map[artifact.SourceKind]ports.Resolver{
		artifact.SourceLocal:  Local{Root: opts.ConfineRoot},
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
type Local struct {
	// Root, when set, confines resolution to that directory. A path that
	// does not resolve (after following symlinks) to Root or below it is
	// refused: the resolution carries a LOCAL-OUTSIDE-ROOT finding and no
	// LocalPath, so the hasher and analyzers never open it. A path that does
	// not exist or cannot be evaluated is refused the same way. Empty means
	// unconfined, which is what the CLI wants on a developer's own machine.
	Root string
}

// Resolve satisfies ports.Resolver.
func (l Local) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	path := src.Ref
	if path == "" {
		path = src.Command
	}
	if l.Root != "" && !within(l.Root, path) {
		return ports.Resolution{PinnedRef: path, Warnings: []finding.Finding{finding.LocalOutsideRoot()}}, nil
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

// within reports whether path, with every symlink followed, is root or lies
// under it. Any error (a missing path, an unreadable link) reports false, so
// confinement fails closed.
func within(root, path string) bool {
	rootReal, err := realAbs(root)
	if err != nil {
		return false
	}
	real, err := realAbs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootReal, real)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// realAbs returns the absolute path of p with every symlink resolved.
func realAbs(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// Inline content-addresses literal text (hooks, rules, context). By convention
// the literal content is carried in Source.Ref.
type Inline struct{}

// Resolve satisfies ports.Resolver.
func (Inline) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	return ports.Resolution{ContentHash: digest.Inline([]byte(src.Ref))}, nil
}
