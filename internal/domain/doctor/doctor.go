// Package doctor models the result of an environment self-check: a list of
// named checks, each with a status and a one-line detail, plus a summary. It is
// pure and IO-free — the CLI gathers the real signals (discovered tools,
// lockfile state, sandbox availability, hooks, server reachability) and records
// each as a Check; this package only classifies and renders them.
package doctor

import (
	"fmt"
	"strings"
)

// Status is a single check's outcome. Only Warn signals something to fix; Info
// is a neutral note (e.g. an opt-in feature that is not configured).
type Status string

const (
	StatusOK   Status = "ok"   // healthy
	StatusWarn Status = "warn" // needs attention
	StatusInfo Status = "info" // neutral / not configured
)

// Check is one named diagnostic result.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// Report is an ordered set of checks.
type Report struct {
	Checks []Check
}

// Add appends a check and returns the report, so checks compose left to right.
func (r Report) Add(name string, s Status, detail string) Report {
	r.Checks = append(r.Checks, Check{Name: name, Status: s, Detail: detail})
	return r
}

// Warnings counts checks that need attention.
func (r Report) Warnings() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == StatusWarn {
			n++
		}
	}
	return n
}

// Healthy reports whether nothing needs attention.
func (r Report) Healthy() bool { return r.Warnings() == 0 }

// Render formats the report as an aligned ASCII block plus a summary line.
func (r Report) Render() string {
	width := 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	var b strings.Builder
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  [%-4s] %-*s  %s\n", c.Status, width, c.Name, c.Detail)
	}
	b.WriteString("\n")
	switch n := r.Warnings(); n {
	case 0:
		b.WriteString("all good\n")
	case 1:
		b.WriteString("1 warning\n")
	default:
		fmt.Fprintf(&b, "%d warnings\n", n)
	}
	return b.String()
}
