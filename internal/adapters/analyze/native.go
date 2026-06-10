// Package analyze runs static analysis over resolved artifact code.
//
// Native provides cheap, always-on Go matchers for high-signal patterns so
// `scan` works with zero external dependencies. The Semgrep runner (semgrep.go)
// is an optional accelerator that degrades gracefully when the binary is
// absent. Findings are mapped to the OWASP Agentic Skills Top 10 taxonomy.
package analyze

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
)

type rule struct {
	id       string
	severity finding.Severity
	owasp    string
	re       *regexp.Regexp
	explain  string
}

// rules is the curated native matcher set. Each pattern is high-signal by
// design; tuning false positives here is what keeps `scan` output credible.
var rules = []rule{
	{
		id: "RCE-PIPE-EXEC", severity: finding.SeverityCritical, owasp: "ASK-01",
		re:      regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`),
		explain: "downloads and executes remote code via a pipe to a shell",
	},
	{
		id: "RCE-POWERSHELL-IEX", severity: finding.SeverityCritical, owasp: "ASK-01",
		re:      regexp.MustCompile(`(?i)\bi(wr|ex)\b[^\n|]*\|\s*iex\b`),
		explain: "downloads and executes remote code via PowerShell Invoke-Expression",
	},
	{
		id: "OBFUSCATION-EVAL", severity: finding.SeverityHigh, owasp: "ASK-05",
		re:      regexp.MustCompile(`\b(eval|Function)\s*\(|\batob\s*\(`),
		explain: "dynamic code evaluation or base64 decoding, a common obfuscation vector",
	},
	{
		id: "SENSITIVE-PATH-READ", severity: finding.SeverityHigh, owasp: "ASK-06",
		re:      regexp.MustCompile(`(?i)(\.ssh/|\.aws/|\bid_rsa\b|\.env\b|\.config/solana|keychain|Login Data)`),
		explain: "references sensitive credential or secret paths",
	},
	{
		id: "EXEC-PRIMITIVE", severity: finding.SeverityMedium, owasp: "ASK-03",
		re:      regexp.MustCompile(`\b(child_process|os/exec|subprocess|Runtime\.exec)\b`),
		explain: "uses a process-execution primitive",
	},
	{
		id: "NPM-INSTALL-HOOK", severity: finding.SeverityHigh, owasp: "ASK-02",
		re:      regexp.MustCompile(`"(pre|post)install"\s*:`),
		explain: "declares an npm install lifecycle script, a classic supply-chain vector",
	},
	{
		id: "PROMPT-INJECTION", severity: finding.SeverityHigh, owasp: "ASK-07",
		re:      regexp.MustCompile(`(?i)(ignore (all )?previous instructions|auto[- ]approve|without (asking|confirmation)|do not (ask|tell|mention))`),
		explain: "contains consent-bypass or prompt-injection language",
	},
}

// Native is the dependency-free analyzer.
type Native struct {
	rules        []rule
	maxFileBytes int64 // files larger than this are skipped (likely assets)
	maxPerRule   int   // cap findings per rule per file to limit noise
}

// NewNative returns the analyzer with the default ruleset and limits.
func NewNative() *Native {
	return &Native{rules: rules, maxFileBytes: 2 << 20, maxPerRule: 5}
}

// Analyze walks the resolved code at root and returns findings. root may be a
// directory or a single file. It never returns an error for ordinary scan
// conditions (unreadable individual files are skipped), keeping scan resilient.
func (n *Native) Analyze(ctx context.Context, _ artifact.Artifact, root string) ([]finding.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var out []finding.Finding
	scanFile := func(path, rel string) {
		fi, err := os.Stat(path)
		if err != nil || fi.Size() > n.maxFileBytes {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil || looksBinary(b) {
			return
		}
		out = append(out, n.scanContent(rel, b)...)
	}

	if !info.IsDir() {
		scanFile(root, filepath.Base(root))
		return out, nil
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if isVendorDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		scanFile(path, filepath.ToSlash(rel))
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

// AnalyzeContent scans an in-memory blob (e.g. an inline hook command) using
// the same ruleset. Findings are labelled with the artifact's name since there
// is no file path. Binary blobs are skipped.
func (n *Native) AnalyzeContent(_ context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error) {
	if looksBinary(content) {
		return nil, nil
	}
	label := a.Name
	if label == "" {
		label = "<inline>"
	}
	return n.scanContent(label, content), nil
}

// scanContent applies every rule line-by-line so findings carry line numbers.
func (n *Native) scanContent(relPath string, content []byte) []finding.Finding {
	var out []finding.Finding
	perRule := map[string]int{}

	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		for _, r := range n.rules {
			if perRule[r.id] >= n.maxPerRule {
				continue
			}
			if r.re.MatchString(text) {
				perRule[r.id]++
				out = append(out, finding.Finding{
					RuleID:      r.id,
					Severity:    r.severity,
					OWASP:       r.owasp,
					File:        relPath,
					Line:        line,
					Snippet:     truncate(strings.TrimSpace(text), 120),
					Explanation: r.explain,
				})
			}
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// vendorDirNames are directories holding third-party dependency code. Analysis
// skips them: flagging pip's or PIL's internals is noise that buries real
// findings in the author's own code. Note this affects analysis only — the
// hasher (internal/adapters/hash) still includes these dirs, because vendored
// code does run and must be part of the integrity anchor.
var vendorDirNames = map[string]bool{
	".git":             true,
	"node_modules":     true,
	"bower_components": true,
	".venv":            true,
	"venv":             true,
	"site-packages":    true,
	"__pycache__":      true,
	".tox":             true,
	".mypy_cache":      true,
	"vendor":           true,
}

// isVendorDir reports whether a directory name is a dependency/vendor dir that
// analysis should skip, including Python package-metadata suffixes.
func isVendorDir(name string) bool {
	if vendorDirNames[name] {
		return true
	}
	return strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info")
}

// looksBinary reports whether the first chunk of b contains a NUL byte.
func looksBinary(b []byte) bool {
	const probe = 8000
	if len(b) > probe {
		b = b[:probe]
	}
	return bytes.IndexByte(b, 0x00) >= 0
}
