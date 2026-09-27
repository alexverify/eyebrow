package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/analyze"
	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/adapters/hash"
	"github.com/alexverify/eyebrow/internal/adapters/resolve"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// checkFinding is one finding in check's output: location and rule only. File
// content (snippet) and free text (explanation) stay out, because install-gate
// callers forward this output into user-visible messages.
type checkFinding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	OWASP    string `json:"owasp,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Blocking bool   `json:"blocking"`
}

type checkReport struct {
	Verdict     string         `json:"verdict"` // "pass" | "block"
	FailOn      string         `json:"failOn"`
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	ContentHash string         `json:"contentHash,omitempty"`
	Findings    []checkFinding `json:"findings"`
}

// runCheck scans one folder as an untrusted skill or plugin: the install gate
// for a package staged before it lands. Local resolution is confined to the
// folder and the resolver is offline; Build is used, never Run, so nothing is
// written. Exit 1 when any finding reaches --fail-on.
func (a *App) runCheck(ctx context.Context, args []string) int {
	fs := a.flagSet("check")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	failOn := fs.String("fail-on", "high", "lowest severity that fails the check (critical|high|medium|low)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(a.Stderr, "check: missing folder (usage: eyebrow check <dir> [--json] [--fail-on high])")
		return ExitUsage
	}
	dir := fs.Arg(0)
	// flag stops at the first positional; parse what follows the folder too.
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(a.Stderr, "check: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	threshold := finding.Severity(*failOn)
	switch threshold {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow:
	default:
		fmt.Fprintf(a.Stderr, "check: unknown --fail-on %q (want critical, high, medium or low)\n", *failOn)
		return ExitUsage
	}
	root, err := checkFolder(dir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "check: %v\n", err)
		return ExitUsage
	}

	svc := scan.New(scan.Deps{
		Discoverer: discover.NewDir(root),
		Resolver:   resolve.NewOfflineRouterWith(resolve.RouterOptions{ConfineRoot: root}),
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyze.NewNative()),
		Clock:      a.Clock,
	})
	lf, err := svc.Build(ctx, []ports.Scope{{Kind: "project", Path: root}})
	if err != nil {
		return a.fail("check", err)
	}
	if len(lf.Artifacts) != 1 {
		return a.fail("check", fmt.Errorf("expected one artifact, got %d", len(lf.Artifacts)))
	}
	e := lf.Artifacts[0]
	rep := checkReport{
		Verdict:     "pass",
		FailOn:      string(threshold),
		Type:        string(e.Type),
		Name:        e.Name,
		ContentHash: e.ContentHash,
		Findings:    []checkFinding{},
	}
	for _, f := range e.Findings {
		blocking := f.Severity.AtLeast(threshold)
		if blocking {
			rep.Verdict = "block"
		}
		rep.Findings = append(rep.Findings, checkFinding{
			RuleID: f.RuleID, Severity: string(f.Severity), OWASP: f.OWASP,
			File: f.File, Line: f.Line, Blocking: blocking,
		})
	}

	if *jsonOut {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return a.fail("check", err)
		}
	} else {
		writeCheckText(a.Stdout, rep)
	}
	if rep.Verdict == "block" {
		return ExitDrift
	}
	return ExitOK
}

// checkFolder returns dir as an absolute path with every symlink resolved, the
// form the confined resolver requires. A folder reached through a symlink
// (macOS $TMPDIR) must not read as outside itself.
func checkFolder(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("folder %q: %w", dir, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("folder %q: %w", dir, err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("folder %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a folder", dir)
	}
	return real, nil
}

func writeCheckText(w io.Writer, r checkReport) {
	blocking := 0
	for _, f := range r.Findings {
		if f.Blocking {
			blocking++
		}
	}
	fmt.Fprintf(w, "check: %s (%s): %s, %d finding(s), %d at or above %s\n",
		r.Name, r.Type, r.Verdict, len(r.Findings), blocking, r.FailOn)
	for _, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "  [%s] %s %s\n", f.Severity, f.RuleID, loc)
	}
}
