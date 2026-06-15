// Package reach classifies whether a finding's file is on a path the artifact
// actually runs (theme H2). A secret-access pattern inside a test fixture, an
// example script, or a vendored dependency is almost always noise — it never
// executes in production — so demoting it cuts the false-positive rate the
// analysis pipeline otherwise suffers.
//
// This is deliberately a *location* heuristic, not a call graph: a zero-
// dependency static binary cannot trace imports across every ecosystem. So it
// only down-ranks findings in conventionally non-runtime locations and never
// deletes a finding — an honest demotion, the same discipline as the H1 diff
// (name the change you can prove, claim nothing you cannot). A future call-graph
// pass could upgrade this to true reachability without changing the seam.
package reach

import "strings"

// Class is a finding file's runtime reachability.
type Class string

const (
	// Reachable: a normal runtime file (the default — we never hide on a guess).
	Reachable Class = "reachable"
	// Inert: a conventionally non-runtime path (tests, examples, fixtures,
	// vendored deps) — a finding here is most likely noise.
	Inert Class = "inert"
)

// inertSegments are path components that, by near-universal convention, hold
// code that does not run in production.
var inertSegments = map[string]bool{
	"test": true, "tests": true, "__tests__": true,
	"__mocks__": true, "mocks": true,
	"spec": true, "specs": true,
	"example": true, "examples": true,
	"fixture": true, "fixtures": true,
	"sample": true, "samples": true,
	"testdata":     true,
	"vendor":       true,
	"node_modules": true,
	".git":         true,
	"bench":        true, "benchmarks": true,
}

// Classify returns the reachability of a file path. An empty path is Reachable:
// with no location we never demote.
func Classify(path string) Class {
	if isInert(path) {
		return Inert
	}
	return Reachable
}

func isInert(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	for _, seg := range strings.Split(p, "/") {
		if inertSegments[seg] {
			return true
		}
	}
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	// Go test files, and the `.test.`/`.spec.` dotted convention (foo.test.js).
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") {
		return true
	}
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}
