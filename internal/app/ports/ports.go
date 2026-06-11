// Package ports declares the interfaces (the "ports" of the hexagon) that the
// application services depend on. Adapters in internal/adapters implement them.
//
// The dependency rule: this package and the services that use it know nothing
// about npm, git, Semgrep, the filesystem, or the CLI. They speak only in
// terms of these interfaces and the pure domain types. That is what makes the
// scan/verify workflows testable with in-memory fakes and what keeps the
// trust-critical logic isolated from messy external surfaces.
package ports

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// Sentinel errors adapters may return so services can react without coupling
// to concrete adapter types.
var (
	// ErrNotImplemented marks an adapter method that is scaffolded but not yet
	// built. Services treat it as a soft, per-artifact skip, never a crash.
	ErrNotImplemented = errors.New("not implemented")
	// ErrUnsupported marks a source kind an adapter intentionally does not
	// handle (e.g. the local resolver asked to resolve an npm source).
	ErrUnsupported = errors.New("unsupported source kind")
	// ErrNoLockfile is returned by LockStore.Read when no lockfile exists.
	ErrNoLockfile = errors.New("no lockfile found")
)

// Scope identifies where to look for artifacts.
type Scope struct {
	Kind string // "global" | "project"
	Path string // project root for project scope; ignored for global
}

// String renders the scope in the canonical form stored on artifacts
// ("global" or "project:<path>").
func (s Scope) String() string {
	if s.Kind == "project" {
		return "project:" + s.Path
	}
	return s.Kind
}

// Discoverer walks tool configs within the given scopes and returns normalized
// artifacts with their Source declarations filled in (but not yet resolved or
// hashed).
type Discoverer interface {
	Discover(ctx context.Context, scopes []Scope) ([]artifact.Artifact, error)
}

// Resolution is the outcome of turning a Source declaration into concrete,
// pinned, content-addressable code (or an integrity anchor for things that
// cannot be hashed locally, like remote URLs).
type Resolution struct {
	PinnedRef   string            // concrete resolved ref (exact version / commit SHA)
	Integrity   string            // upstream-attested integrity (e.g. npm sha512-…)
	CertSPKI    string            // TLS SPKI pin for remote (url) sources
	LocalPath   string            // non-empty => a directory to hash and analyze
	ContentHash string            // non-empty => already content-addressed; skip hashing
	Warnings    []finding.Finding // resolution-time findings (e.g. unpinned @latest)
}

// Resolver turns a Source into a Resolution. It returns ErrUnsupported for
// kinds it does not handle, letting a router delegate to per-kind resolvers.
type Resolver interface {
	Resolve(ctx context.Context, src artifact.Source) (Resolution, error)
}

// Hasher computes the canonical content digest and per-file hashes for a
// directory on disk, using the domain digest algorithm.
type Hasher interface {
	Hash(ctx context.Context, root string) (contentHash string, files []artifact.FileRef, err error)
}

// Analyzer runs static analysis over an artifact's resolved code, returning
// findings mapped to the OWASP taxonomy. Analyze scans a directory or file on
// disk; AnalyzeContent scans an in-memory blob (e.g. an inline hook command
// that has no file on disk).
type Analyzer interface {
	Analyze(ctx context.Context, a artifact.Artifact, root string) ([]finding.Finding, error)
	AnalyzeContent(ctx context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error)
}

// LockStore reads and writes agentlock.json.
type LockStore interface {
	Read(ctx context.Context, path string) (lockfile.Lockfile, error)
	Write(ctx context.Context, path string, lf lockfile.Lockfile) error
	Exists(path string) bool
}

// Signer produces and verifies detached signatures over canonical bytes
// (ed25519 for the MVP; a cosign adapter can satisfy the same port later).
type Signer interface {
	Sign(data []byte) (string, error)
	Verify(data []byte, sig string) error
}

// LockfileVerifier checks that a lockfile carries a valid signature from a
// trusted key. It returns nil when the signature verifies.
type LockfileVerifier interface {
	VerifyLockfile(lf lockfile.Lockfile) error
}

// AuditSink records shim audit events (see internal/domain/audit). Emitting
// must be cheap and safe to call from the relay hot path.
type AuditSink interface {
	Emit(ctx context.Context, e audit.Event) error
}

// Reporter renders results for humans and machines.
type Reporter interface {
	Scan(w io.Writer, lf lockfile.Lockfile) error
	Verify(w io.Writer, d lockfile.Diff) error
	List(w io.Writer, lf lockfile.Lockfile) error
}

// Clock abstracts time so lockfile timestamps are deterministic in tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Now satisfies Clock.
func (f ClockFunc) Now() time.Time { return f() }
