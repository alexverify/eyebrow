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

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// Deps are the collaborators verify needs.
type Deps struct {
	Builder          *scan.Service // computes the current state
	Lock             ports.LockStore
	Reporter         ports.Reporter
	Verifier         ports.LockfileVerifier // optional; required only for policy.RequireSignature
	ApprovalVerifier ports.ApprovalVerifier // optional; required only for policy.RequireSignedApproval
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
		if opts.Policy.RequireSignature {
			if v := s.signatureViolation(locked); v != nil {
				pres.Violations = append(pres.Violations, *v)
			}
		}
		if opts.Policy.RequireSignedApproval {
			pres.Violations = append(pres.Violations, s.approvalViolations(locked)...)
		}
		if !pres.OK() {
			ok = false
		}
	}
	return Result{Diff: diff, Policy: pres, OK: ok}, nil
}

// approvalViolations checks that every approved artifact carries a valid
// signature from a trusted key. Artifacts that are not approved are left to
// the RequireApproval check (implied on by Normalize), so this reports only
// approvals that exist but are unsigned, forged, or stale (content moved).
func (s *Service) approvalViolations(locked lockfile.Lockfile) []policy.Violation {
	var out []policy.Violation
	if s.deps.ApprovalVerifier == nil {
		return []policy.Violation{{Kind: "unsigned_approval", Detail: "no signing key available to verify approvals"}}
	}
	for _, e := range locked.Artifacts {
		if e.Approval == nil || e.Approval.Status != "approved" {
			continue
		}
		if err := s.deps.ApprovalVerifier.VerifyApproval(e); err != nil {
			out = append(out, policy.Violation{
				Kind: "unsigned_approval", ID: e.ID, Name: e.Name, Detail: err.Error(),
			})
		}
	}
	return out
}

// signatureViolation returns a policy violation if the locked lockfile is not
// validly signed, or nil if it is.
func (s *Service) signatureViolation(locked lockfile.Lockfile) *policy.Violation {
	if s.deps.Verifier == nil {
		return &policy.Violation{Kind: "signature", Detail: "no signing key available to verify the lockfile"}
	}
	if err := s.deps.Verifier.VerifyLockfile(locked); err != nil {
		return &policy.Violation{Kind: "signature", Detail: err.Error()}
	}
	return nil
}
