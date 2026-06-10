package analyze

import (
	"context"
	"os/exec"

	"github.com/agentguard/agentguard/internal/domain/artifact"
	"github.com/agentguard/agentguard/internal/domain/finding"
)

// Semgrep is an optional static-analysis accelerator that shells out to the
// `semgrep` binary with agentguard's curated rules pack. It is a documented
// seam: when semgrep is not installed it contributes nothing and never errors,
// so `scan` always works on the native matchers alone.
//
// Wiring the actual invocation (run `semgrep --json`, map results to
// finding.Finding with OWASP categories) is intentionally deferred; see
// rules/README.md and docs/architecture/ARCHITECTURE.md.
type Semgrep struct {
	RulesDir string
	bin      string // resolved path; empty when semgrep is unavailable
}

// NewSemgrep resolves the semgrep binary (if present) and points it at the
// given rules directory.
func NewSemgrep(rulesDir string) *Semgrep {
	bin, _ := exec.LookPath("semgrep")
	return &Semgrep{RulesDir: rulesDir, bin: bin}
}

// Available reports whether the semgrep binary was found on PATH.
func (s *Semgrep) Available() bool { return s.bin != "" }

// Analyze runs semgrep over root. Until the invocation is wired it returns no
// findings; an absent binary is likewise a no-op, never an error.
func (s *Semgrep) Analyze(_ context.Context, _ artifact.Artifact, _ string) ([]finding.Finding, error) {
	if !s.Available() {
		return nil, nil
	}
	// TODO: exec semgrep --json --config <RulesDir> <root>, parse, and map to
	// finding.Finding. Deferred to keep the MVP dependency-free and the native
	// matchers authoritative.
	return nil, nil
}
