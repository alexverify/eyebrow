// Package apptest provides in-memory fakes implementing the application ports.
// They let the scan and verify use cases be tested end-to-end with no
// filesystem, network, or subprocess access — the central benefit of the
// ports-and-adapters design.
package apptest

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// Discoverer returns a fixed set of artifacts.
type Discoverer struct {
	Artifacts []artifact.Artifact
	Err       error
}

// Discover satisfies ports.Discoverer.
func (d Discoverer) Discover(context.Context, []ports.Scope) ([]artifact.Artifact, error) {
	// Return copies so callers mutating results don't affect the fixture.
	out := make([]artifact.Artifact, len(d.Artifacts))
	copy(out, d.Artifacts)
	return out, d.Err
}

// Resolver delegates to Func, or echoes the Source's Ref as a local path.
type Resolver struct {
	Func func(src artifact.Source) (ports.Resolution, error)
}

// Resolve satisfies ports.Resolver.
func (r Resolver) Resolve(_ context.Context, src artifact.Source) (ports.Resolution, error) {
	if r.Func != nil {
		return r.Func(src)
	}
	return ports.Resolution{LocalPath: src.Ref}, nil
}

// Hasher returns a fixed hash and file list.
type Hasher struct {
	HashValue string
	Files     []artifact.FileRef
	ModTime   time.Time
	Err       error
}

// Hash satisfies ports.Hasher.
func (h Hasher) Hash(context.Context, string) (string, []artifact.FileRef, time.Time, error) {
	hv := h.HashValue
	if hv == "" {
		hv = "sha256-fake"
	}
	return hv, h.Files, h.ModTime, h.Err
}

// Analyzer returns fixed findings.
type Analyzer struct {
	Findings []finding.Finding
	Err      error
}

// Analyze satisfies ports.Analyzer.
func (a Analyzer) Analyze(context.Context, artifact.Artifact, string) ([]finding.Finding, error) {
	return a.Findings, a.Err
}

// AnalyzeContent satisfies ports.Analyzer.
func (a Analyzer) AnalyzeContent(context.Context, artifact.Artifact, []byte) ([]finding.Finding, error) {
	return a.Findings, a.Err
}

// LockStore is an in-memory ports.LockStore keyed by path.
type LockStore struct {
	store map[string]lockfile.Lockfile
}

// NewLockStore returns an empty in-memory lock store.
func NewLockStore() *LockStore { return &LockStore{store: map[string]lockfile.Lockfile{}} }

// Read satisfies ports.LockStore.
func (s *LockStore) Read(_ context.Context, path string) (lockfile.Lockfile, error) {
	lf, ok := s.store[path]
	if !ok {
		return lockfile.Lockfile{}, ports.ErrNoLockfile
	}
	return lf, nil
}

// Write satisfies ports.LockStore.
func (s *LockStore) Write(_ context.Context, path string, lf lockfile.Lockfile) error {
	s.store[path] = lf
	return nil
}

// Exists satisfies ports.LockStore.
func (s *LockStore) Exists(path string) bool { _, ok := s.store[path]; return ok }

// Reporter discards output; tests assert on returned values, not text.
type Reporter struct{}

// Scan satisfies ports.Reporter.
func (Reporter) Scan(io.Writer, lockfile.Lockfile) error { return nil }

// Verify satisfies ports.Reporter.
func (Reporter) Verify(io.Writer, lockfile.Diff) error { return nil }

// List satisfies ports.Reporter.
func (Reporter) List(io.Writer, lockfile.Lockfile) error { return nil }

// AuditSink records emitted events in memory. Safe for concurrent emitters —
// the shim relay audits from two goroutines.
type AuditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

// Emit satisfies ports.AuditSink.
func (s *AuditSink) Emit(_ context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Events returns a copy of everything emitted so far.
func (s *AuditSink) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

// FixedClock returns a constant time so lockfiles are byte-stable in tests.
type FixedClock struct{ T time.Time }

// Now satisfies ports.Clock.
func (c FixedClock) Now() time.Time { return c.T }
