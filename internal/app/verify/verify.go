// Package verify implements the `verify` use case — the rug-pull detector.
//
// It recomputes the current inventory (reusing the scan pipeline), reads the
// approved lockfile, diffs them, and decides pass/fail. In CI mode it also
// fails on newly introduced findings at or above a severity threshold.
package verify

import (
	"context"
	"fmt"
	"io"

	"github.com/agentguard/agentguard/internal/app/ports"
	"github.com/agentguard/agentguard/internal/app/scan"
	"github.com/agentguard/agentguard/internal/domain/finding"
	"github.com/agentguard/agentguard/internal/domain/lockfile"
)

// Deps are the collaborators verify needs.
type Deps struct {
	Builder  *scan.Service // computes the current state
	Lock     ports.LockStore
	Reporter ports.Reporter
}

// Service orchestrates verification.
type Service struct {
	deps Deps
}

// New constructs a verify Service.
func New(d Deps) *Service { return &Service{deps: d} }

// Options parameterize a verify run.
type Options struct {
	Scopes       []ports.Scope
	LockfilePath string
	CI           bool             // strict mode: also gate on new findings
	Threshold    finding.Severity // CI new-findings threshold (default: high)
}

// Result captures the verification outcome. OK is the single source of truth
// the CLI maps to an exit code.
type Result struct {
	Diff        lockfile.Diff
	NewFindings []finding.Finding
	OK          bool
}

// Run reads the locked snapshot, rebuilds the current one, compares them, and
// reports. It returns ports.ErrNoLockfile (wrapped) when nothing is locked yet.
func (s *Service) Run(ctx context.Context, opts Options, out io.Writer) (Result, error) {
	locked, err := s.deps.Lock.Read(ctx, opts.LockfilePath)
	if err != nil {
		return Result{}, fmt.Errorf("read lockfile: %w", err)
	}

	current, err := s.deps.Builder.Build(ctx, opts.Scopes)
	if err != nil {
		return Result{}, err
	}

	diff := lockfile.Compare(locked, current)

	var newFindings []finding.Finding
	if opts.CI {
		threshold := opts.Threshold
		if threshold == "" {
			threshold = finding.SeverityHigh
		}
		newFindings = lockfile.NewFindings(locked, current, threshold)
	}

	if err := s.deps.Reporter.Verify(out, diff); err != nil {
		return Result{}, fmt.Errorf("report: %w", err)
	}

	ok := !diff.HasDrift()
	if opts.CI && len(newFindings) > 0 {
		ok = false
	}
	return Result{Diff: diff, NewFindings: newFindings, OK: ok}, nil
}
