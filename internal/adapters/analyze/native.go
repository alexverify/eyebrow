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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
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
		// .env counts only as a file name: the character before the dot must
		// not be a word character or a dot, so process.env, import.meta.env
		// and a ...env spread (ordinary JavaScript) do not match.
		re:      regexp.MustCompile(`(?i)(\.ssh/|\.aws/|\bid_rsa\b|(^|[^\w.])\.env\b|\.config/solana|keychain|Login Data)`),
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
		re:      regexp.MustCompile(`(?i)(ignore (all )?previous instructions|auto[- ]approve|without (asking|confirmation)|do not (ask|tell|mention)|bypass (the )?approval|skip (the )?confirmation|disable safety)`),
		explain: "contains consent-bypass or prompt-injection language",
	},
	{
		id: "SSRF-CLOUD-METADATA", severity: finding.SeverityCritical, owasp: "ASK-08",
		re:      regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.(com|net))`),
		explain: "accesses a cloud instance metadata endpoint (SSRF / credential theft)",
	},
	{
		id: "EXFIL-SUSPICIOUS-HOST", severity: finding.SeverityHigh, owasp: "ASK-04",
		re:      regexp.MustCompile(`(?i)(webhook\.site|pastebin\.com|requestbin|ngrok\.(io|app)|transfer\.sh|0x0\.st|termbin\.com)`),
		explain: "sends data to a host commonly used for exfiltration",
	},
	{
		id: "REVERSE-SHELL", severity: finding.SeverityCritical, owasp: "ASK-01",
		re:      regexp.MustCompile(`(?i)(/dev/tcp/|\bnc\b[^\n]*\s-e\b|\bncat\b[^\n]*\s-e\b|bash\s+-i\b|socat\b[^\n]*exec)`),
		explain: "opens a reverse shell",
	},
	{
		id: "ENCODED-EXEC", severity: finding.SeverityHigh, owasp: "ASK-05",
		re:      regexp.MustCompile(`(?i)base64\s+(-d|--decode)\b[^\n]*\|\s*(ba)?sh\b`),
		explain: "decodes a base64 blob and pipes it to a shell",
	},
	{
		id: "WALLET-THEFT", severity: finding.SeverityHigh, owasp: "ASK-06",
		re:      regexp.MustCompile(`(?i)(wallet\.dat|\belectrum\b|metamask|\bmnemonic\b|seed phrase)`),
		explain: "references cryptocurrency wallet or seed-phrase material",
	},
}

// RuleInfo describes one native rule without its pattern, for callers that
// render findings or build allow lists.
type RuleInfo struct {
	ID          string
	Severity    finding.Severity
	OWASP       string
	Explanation string
}

// RuleTable returns the native rule set in evaluation order, followed by the
// rules the scan pipeline itself raises without a pattern match.
func RuleTable() []RuleInfo {
	pipeline := pipelineRules()
	out := make([]RuleInfo, 0, len(rules)+len(pipeline))
	for _, r := range rules {
		out = append(out, RuleInfo{ID: r.id, Severity: r.severity, OWASP: r.owasp, Explanation: r.explain})
	}
	return append(out, pipeline...)
}

// pipelineRules lists findings the pipeline raises outside pattern matching,
// so their ids are reserved in RuleTable like any native rule. The finding
// package owns the registry; this only reshapes it.
func pipelineRules() []RuleInfo {
	var out []RuleInfo
	for _, f := range finding.PipelineRules() {
		out = append(out, RuleInfo{ID: f.RuleID, Severity: f.Severity, OWASP: f.OWASP, Explanation: f.Explanation})
	}
	return out
}

// Native is the dependency-free analyzer.
type Native struct {
	rules        []rule
	maxFileBytes int64 // files larger than this are skipped (likely assets)
	maxPerRule   int   // cap findings per rule per file to limit noise
	strict       bool
}

// NewNative returns the analyzer with the default ruleset and limits.
func NewNative() *Native {
	return &Native{rules: rules, maxFileBytes: 2 << 20, maxPerRule: 5}
}

// NewStrictNative returns the analyzer `check` uses on an untrusted folder.
// It analyzes every directory (vendor dirs and .git included), raises the file
// limit to 32 MiB, and reports instead of skipping: a file it cannot analyze
// yields CHECK-UNSCANNED-FILE and an entry it will not open (a symlink out of
// the folder, a named pipe, a device) yields CHECK-UNSAFE-ENTRY.
func NewStrictNative() *Native {
	return &Native{rules: rules, maxFileBytes: 32 << 20, maxPerRule: 5, strict: true}
}

// Analyze walks the resolved code at root and returns findings. root may be a
// directory or a single file. It never returns an error for ordinary scan
// conditions (unreadable individual files are skipped, or reported in strict
// mode), keeping scan resilient.
func (n *Native) Analyze(ctx context.Context, _ artifact.Artifact, root string) ([]finding.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var out []finding.Finding
	unscanned := func(rel, reason string) {
		if n.strict {
			out = append(out, finding.UnscannedFile(rel, reason))
		}
	}
	scanFile := func(path, rel string) {
		fi, err := os.Stat(path)
		if err != nil {
			unscanned(rel, "unreadable")
			return
		}
		if fi.Size() > n.maxFileBytes {
			unscanned(rel, fmt.Sprintf("larger than %d MiB", n.maxFileBytes>>20))
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			unscanned(rel, "unreadable")
			return
		}
		if looksBinary(b) {
			unscanned(rel, "binary content")
			return
		}
		out = append(out, n.scanContent(rel, b)...)
	}

	if !info.IsDir() {
		scanFile(root, filepath.Base(root))
		return out, nil
	}

	// Symlink targets are judged against the resolved root, so a folder
	// reached through a symlink (macOS $TMPDIR) does not read as outside itself.
	realRoot := root
	if n.strict {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			realRoot = r
		}
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if !n.strict || path == root {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, finding.UnscannedFile(filepath.ToSlash(rel), "unreadable"))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if !n.strict && isVendorDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			if n.strict {
				if f, ok := unsafeEntry(realRoot, path, rel, d.Type()); ok {
					out = append(out, f)
				}
			}
			return nil
		}
		scanFile(path, rel)
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

// unsafeEntry judges a non-regular entry without opening it. A symlink that
// resolves inside realRoot is harmless (its target is walked on its own); one
// that resolves outside, or not at all, is reported, as is any pipe, device or
// socket.
func unsafeEntry(realRoot, path, rel string, mode fs.FileMode) (finding.Finding, bool) {
	if mode&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return finding.UnsafeEntry(rel, "unresolvable symlink"), true
		}
		if r, err := filepath.Rel(realRoot, target); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
			return finding.UnsafeEntry(rel, "symlink pointing outside the folder"), true
		}
		return finding.Finding{}, false
	}
	return finding.UnsafeEntry(rel, "named pipe or device"), true
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
