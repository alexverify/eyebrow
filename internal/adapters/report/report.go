// Package report renders scan, verify, and list results. It offers a Text
// reporter for humans and a JSON reporter for machines (--json / CI), both
// satisfying ports.Reporter. Output is dependency-free: no color libraries.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// JSON renders machine-readable output.
type JSON struct{}

func encode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Scan writes the full lockfile as JSON.
func (JSON) Scan(w io.Writer, lf lockfile.Lockfile) error { return encode(w, lf) }

// Verify writes the diff as JSON.
func (JSON) Verify(w io.Writer, d lockfile.Diff) error { return encode(w, d) }

// List writes the artifacts as JSON.
func (JSON) List(w io.Writer, lf lockfile.Lockfile) error { return encode(w, lf.Artifacts) }

// Text renders human-readable output.
type Text struct{}

// Scan prints an inventory summary with per-severity finding counts.
func (Text) Scan(w io.Writer, lf lockfile.Lockfile) error {
	fmt.Fprintf(w, "agentguard scan — %d artifact(s), generated %s\n",
		len(lf.Artifacts), lf.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	for _, e := range lf.Artifacts {
		fmt.Fprintf(w, "\n  %s  [%s/%s]  scope=%s\n", e.Name, e.Tool, e.Type, e.Scope)
		if e.ContentHash != "" {
			fmt.Fprintf(w, "    hash: %s\n", e.ContentHash)
		} else {
			fmt.Fprintf(w, "    hash: (unresolved)\n")
		}
		writeFindings(w, e.Findings)
	}
	return nil
}

// Verify prints drift, or a clean confirmation.
func (Text) Verify(w io.Writer, d lockfile.Diff) error {
	if !d.HasDrift() {
		fmt.Fprintln(w, "verify: OK — no drift detected against the lockfile")
		return nil
	}
	fmt.Fprintf(w, "verify: DRIFT — %d change(s) detected:\n", len(d.Changes))
	for _, c := range d.Changes {
		fmt.Fprintf(w, "  [%s] %s (%s)\n", c.Kind, c.Name, c.ID)
		if c.Old != "" || c.New != "" {
			fmt.Fprintf(w, "    old: %s\n    new: %s\n", c.Old, c.New)
		}
	}
	return nil
}

// List prints a compact inventory.
func (Text) List(w io.Writer, lf lockfile.Lockfile) error {
	for _, e := range lf.Artifacts {
		worst := finding.Max(e.Findings)
		fmt.Fprintf(w, "%-24s %-12s %-12s %-8s %s\n", e.Name, e.Tool, e.Type, worst, e.Scope)
	}
	return nil
}

func writeFindings(w io.Writer, fs []finding.Finding) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "    findings: none")
		return
	}
	counts := map[finding.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "    findings: %d (critical=%d high=%d medium=%d low=%d info=%d)\n",
		len(fs),
		counts[finding.SeverityCritical], counts[finding.SeverityHigh],
		counts[finding.SeverityMedium], counts[finding.SeverityLow],
		counts[finding.SeverityInfo])
	for _, f := range fs {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "      - [%s] %s %s %s\n", f.Severity, f.RuleID, f.OWASP, loc)
	}
}
