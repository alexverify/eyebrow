// Package verify implements the `verify` use case — the rug-pull detector.
//
// It recomputes the current inventory (reusing the scan pipeline), reads the
// approved lockfile, diffs them, and decides pass/fail. In CI mode it also
// applies the team policy (severity threshold, rule suppression, required
// approval) via the pure policy.Evaluate.
package verify

import (
	"context"
	"fmt"
	"io"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/app/scan"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
	"github.com/alexverify/agentguard/internal/domain/policy"
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
	CI           bool          // strict mode: also apply the policy gate
	Policy       policy.Policy // the team policy (defaults applied by Evaluate)
}

// Result captures the verification outcome. OK is the single source of truth
// the CLI maps to an exit code.
type Result struct {
	Diff   lockfile.Diff
	Policy policy.Result
	OK     bool
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

	if err := s.deps.Reporter.Verify(out, diff); err != nil {
		return Result{}, fmt.Errorf("report: %w", err)
	}

	ok := !diff.HasDrift()
	var pres policy.Result
	if opts.CI {
		pres = policy.Evaluate(opts.Policy, locked, current)
		if !pres.OK() {
			ok = false
		}
	}
	return Result{Diff: diff, Policy: pres, OK: ok}, nil
}
