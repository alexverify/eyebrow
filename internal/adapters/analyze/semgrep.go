package analyze

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/platform/run"
)

// Semgrep is an optional static-analysis accelerator that shells out to the
// `semgrep` binary with assay's curated rules pack (see rules/). It is a
// soft layer by contract: when semgrep is not installed, the rules dir is
// absent, or the run/parse fails, it contributes nothing and never errors —
// `scan` always works on the native matchers alone, which stay authoritative.
type Semgrep struct {
	RulesDir string
	bin      string // resolved path; empty when semgrep is unavailable
	runner   run.Runner
}

// NewSemgrep resolves the semgrep binary (if present) and points it at the
// given rules directory.
func NewSemgrep(rulesDir string) *Semgrep {
	bin, _ := exec.LookPath("semgrep")
	return &Semgrep{RulesDir: rulesDir, bin: bin, runner: run.OS{}}
}

// Available reports whether the semgrep binary was found on PATH.
func (s *Semgrep) Available() bool { return s.bin != "" }

// semgrepArgs builds the semgrep invocation: JSON output, the curated rules,
// and the same vendored-dir exclusions the native matchers apply (sorted so
// the command line is deterministic).
func semgrepArgs(rulesDir, root string) []string {
	args := []string{"scan", "--json", "--quiet", "--config", rulesDir}
	names := make([]string, 0, len(vendorDirNames))
	for name := range vendorDirNames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "--exclude", name)
	}
	return append(args, root)
}

// semgrepOutput is the slice of `semgrep --json` we consume.
type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Severity string         `json:"severity"`
			Message  string         `json:"message"`
			Lines    string         `json:"lines"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

// Analyze runs semgrep over root and maps its results to findings. Every
// failure mode of this optional layer degrades to "no findings".
func (s *Semgrep) Analyze(ctx context.Context, _ artifact.Artifact, root string) ([]finding.Finding, error) {
	if !s.Available() {
		return nil, nil
	}
	if _, err := os.Stat(s.RulesDir); err != nil {
		return nil, nil
	}
	out, err := s.runner.Run(ctx, s.bin, semgrepArgs(s.RulesDir, root)...)
	if err != nil {
		return nil, nil
	}
	var parsed semgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, nil
	}

	var fs []finding.Finding
	for _, r := range parsed.Results {
		fs = append(fs, finding.Finding{
			RuleID:      semgrepRuleID(r.CheckID),
			Severity:    semgrepSeverity(r.Extra.Severity),
			OWASP:       semgrepOWASP(r.Extra.Metadata),
			File:        relToRoot(r.Path, root),
			Line:        r.Start.Line,
			Snippet:     strings.TrimSpace(r.Extra.Lines),
			Explanation: r.Extra.Message,
		})
	}
	return fs, nil
}

// AnalyzeContent is a no-op: Semgrep operates on files, not in-memory blobs.
func (s *Semgrep) AnalyzeContent(_ context.Context, _ artifact.Artifact, _ []byte) ([]finding.Finding, error) {
	return nil, nil
}

// semgrepRuleID turns a dotted check_id ("rules.curl-pipe-shell") into a
// namespaced rule ID ("SEMGREP-CURL-PIPE-SHELL") so semgrep findings never
// collide with native rule IDs in policies.
func semgrepRuleID(checkID string) string {
	parts := strings.Split(checkID, ".")
	return "SEMGREP-" + strings.ToUpper(parts[len(parts)-1])
}

// semgrepSeverity maps semgrep's three levels onto the domain scale. Critical
// is reserved for native matchers — a semgrep rule wanting critical impact
// should be promoted to a native rule.
func semgrepSeverity(s string) finding.Severity {
	switch s {
	case "ERROR":
		return finding.SeverityHigh
	case "WARNING":
		return finding.SeverityMedium
	case "INFO":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// semgrepOWASP reads the OWASP Agentic Skills category from rule metadata.
func semgrepOWASP(meta map[string]any) string {
	if v, ok := meta["owasp-agentic"].(string); ok {
		return v
	}
	return ""
}

// relToRoot renders a result path relative to the scanned root with POSIX
// separators, matching how native findings are recorded.
func relToRoot(path, root string) string {
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
