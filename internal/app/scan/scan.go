// Package scan implements the `scan` use case: discover artifacts, resolve and
// pin their sources, hash them, run static analysis, and assemble a lockfile.
//
// The service depends only on ports and domain types, so the entire pipeline
// can be exercised with in-memory fakes (see scan_test.go).
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/buildinfo"
	"github.com/alexverify/eyebrow/internal/domain/advisory"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// Deps are the collaborators the scan service needs. All are interfaces.
type Deps struct {
	Discoverer ports.Discoverer
	Resolver   ports.Resolver
	Hasher     ports.Hasher
	Analyzer   ports.Analyzer
	Lock       ports.LockStore
	Reporter   ports.Reporter
	Clock      ports.Clock
	Snapshots  ports.SnapshotSink // optional: capture file bytes for the H1b line diff
	Generator  string             // recorded in the lockfile; defaults to the build UA
}

// Service orchestrates the scan pipeline.
type Service struct {
	deps Deps
}

// New constructs a Service, applying sensible defaults for optional deps.
func New(d Deps) *Service {
	if d.Clock == nil {
		d.Clock = ports.ClockFunc(time.Now)
	}
	if d.Generator == "" {
		d.Generator = buildinfo.UserAgent()
	}
	return &Service{deps: d}
}

// Options parameterize a scan run.
type Options struct {
	Scopes       []ports.Scope
	LockfilePath string
}

// Build runs the read-only pipeline and returns the assembled lockfile without
// persisting it. verify reuses this to compute the current environment state.
func (s *Service) Build(ctx context.Context, scopes []ports.Scope) (lockfile.Lockfile, error) {
	arts, err := s.deps.Discoverer.Discover(ctx, scopes)
	if err != nil {
		return lockfile.Lockfile{}, fmt.Errorf("discover: %w", err)
	}
	for i := range arts {
		if err := s.enrich(ctx, &arts[i]); err != nil {
			return lockfile.Lockfile{}, fmt.Errorf("artifact %q: %w", arts[i].Name, err)
		}
		// Match against the known-malicious feed last, so the content hash set
		// during enrich is available. Runs for every artifact regardless of how
		// resolution went — a known-bad package that failed to pin still gets
		// flagged by name or source.
		for _, adv := range advisory.Match(advisory.Default(), arts[i].Name, arts[i].Source.Ref, arts[i].ContentHash) {
			arts[i].Findings = append(arts[i].Findings, adv.AsFinding())
		}
	}
	return lockfile.Build(arts, s.deps.Clock.Now().UTC(), s.deps.Generator), nil
}

// Run builds the lockfile, persists it, and writes a report to out.
func (s *Service) Run(ctx context.Context, opts Options, out io.Writer) (lockfile.Lockfile, error) {
	lf, err := s.Build(ctx, opts.Scopes)
	if err != nil {
		return lf, err
	}
	if err := s.deps.Lock.Write(ctx, opts.LockfilePath, lf); err != nil {
		return lf, fmt.Errorf("write lockfile: %w", err)
	}
	if err := s.deps.Reporter.Scan(out, lf); err != nil {
		return lf, fmt.Errorf("report: %w", err)
	}
	return lf, nil
}

// enrich resolves, hashes, and analyzes a single artifact in place.
//
// Resolution that is merely unsupported or not-yet-built degrades to a finding
// rather than failing the whole scan: a security tool must still produce a
// useful inventory even when it can't pin every source.
func (s *Service) enrich(ctx context.Context, a *artifact.Artifact) error {
	res, err := s.deps.Resolver.Resolve(ctx, a.Source)
	if err != nil {
		// Resolution failure for one artifact must never abort the whole scan:
		// a security tool still has to produce a useful inventory. We record
		// the inability to establish integrity as a finding and move on.
		// "Not yet supported" is a softer signal than an outright failure.
		if errors.Is(err, ports.ErrUnsupported) || errors.Is(err, ports.ErrNotImplemented) {
			a.Findings = append(a.Findings, finding.Finding{
				RuleID:      "RESOLVE-UNSUPPORTED",
				Severity:    finding.SeverityMedium,
				OWASP:       "ASK-02",
				Explanation: fmt.Sprintf("source kind %q cannot be resolved yet; its integrity cannot be locked", a.Source.Kind),
			})
			return nil
		}
		a.Findings = append(a.Findings, finding.Finding{
			RuleID:      "RESOLVE-FAILED",
			Severity:    finding.SeverityHigh,
			OWASP:       "ASK-02",
			Explanation: "could not resolve source to verifiable code: " + err.Error(),
		})
		return nil
	}

	if res.PinnedRef != "" {
		a.Source.Ref = res.PinnedRef
	}
	if res.Integrity != "" {
		a.Source.Integrity = res.Integrity
	}
	if res.CertSPKI != "" {
		a.Source.CertSPKI = res.CertSPKI
	}
	if res.Provenance != "" {
		a.Source.Provenance = res.Provenance
	}
	a.Findings = append(a.Findings, res.Warnings...)

	switch {
	case res.LocalPath != "":
		hash, files, modTime, err := s.deps.Hasher.Hash(ctx, res.LocalPath)
		if err != nil {
			return fmt.Errorf("hash: %w", err)
		}
		a.ContentHash = hash
		a.Files = files
		a.ModifiedAt = modTime

		// Capture the bytes for the line-level drift diff (H1b). Best-effort:
		// the diff is an enhancement, so a capture error never fails the scan.
		if s.deps.Snapshots != nil {
			_ = s.deps.Snapshots.Capture(ctx, hash, res.LocalPath)
		}

		fs, err := s.deps.Analyzer.Analyze(ctx, *a, res.LocalPath)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}
		a.Findings = append(a.Findings, fs...)
	case res.ContentHash != "":
		// Remote/inline sources are content-addressed by the resolver itself.
		a.ContentHash = res.ContentHash
		// Inline sources (e.g. hooks) have no file on disk, but their literal
		// content still needs scanning — a hook running `curl | sh` must be
		// flagged, not just hashed for drift.
		if a.Source.Kind == artifact.SourceInline && a.Source.Ref != "" {
			fs, err := s.deps.Analyzer.AnalyzeContent(ctx, *a, []byte(a.Source.Ref))
			if err != nil {
				return fmt.Errorf("analyze inline: %w", err)
			}
			a.Findings = append(a.Findings, fs...)
		}
	}
	return nil
}
