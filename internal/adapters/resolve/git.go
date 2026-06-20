package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/platform/run"
)

// Git resolves git sources by pinning the requested ref to a concrete commit
// SHA — the SHA is the integrity anchor. Content hashing of cloned trees is a
// follow-up; the SHA alone makes drift detectable.
type Git struct {
	Runner run.Runner
}

// NewGit builds a Git resolver.
func NewGit(r run.Runner) Git { return Git{Runner: r} }

// Resolve satisfies ports.Resolver.
func (g Git) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	repoURL, ref := parseGitRef(src.Ref)
	if repoURL == "" {
		return ports.Resolution{}, fmt.Errorf("git: empty repository URL in %q", src.Ref)
	}

	out, err := g.Runner.Run(ctx, "git", "ls-remote", repoURL, ref)
	if err != nil {
		return ports.Resolution{}, fmt.Errorf("git ls-remote %s %s: %w", repoURL, ref, err)
	}
	sha := firstField(out)
	if sha == "" {
		if looksLikeSHA(ref) {
			sha = ref
		} else {
			return ports.Resolution{}, fmt.Errorf("git: could not resolve ref %q in %s", ref, repoURL)
		}
	}

	var warnings []finding.Finding
	if !looksLikeSHA(ref) {
		warnings = append(warnings, finding.Finding{
			RuleID: "UNPINNED-GIT", Severity: finding.SeverityHigh, OWASP: "ASK-02",
			Explanation: fmt.Sprintf("git ref %q is mutable; pin to a commit SHA so the code is locked", ref),
		})
	}

	res := ports.Resolution{PinnedRef: repoURL + "#" + sha, Warnings: warnings}
	// Best-effort: a commit signed by a trusted key satisfies the top
	// provenance rung. `git verify-commit` exits zero only on a valid
	// signature, so the exit code alone is the signal. The object must be
	// available to git locally; when it is not (the common remote-only case)
	// or the commit is unsigned, the lookup degrades to no provenance — an
	// absent rung is information, not a failure.
	if _, verr := g.Runner.Run(ctx, "git", "verify-commit", sha); verr == nil {
		res.Provenance = gitSignaturePredicate
	}
	return res, nil
}

// gitSignaturePredicate marks a source whose pinned commit carries a verified
// signature, recorded on Source.Provenance so the ladder's top rung is met.
const gitSignaturePredicate = "git-signed-commit"

// parseGitRef splits a git source ref into a repository URL and a ref, dropping
// any "git+" scheme prefix. Missing refs default to HEAD.
func parseGitRef(ref string) (repoURL, gitRef string) {
	ref = strings.TrimPrefix(ref, "git+")
	if i := strings.LastIndex(ref, "#"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, "HEAD"
}

// firstField returns the first whitespace-delimited token of out's first line.
func firstField(out []byte) string {
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// looksLikeSHA reports whether s is a hex commit id (7–40 chars).
func looksLikeSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
