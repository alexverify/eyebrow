package reach

import "testing"

func TestReachableRuntimePaths(t *testing.T) {
	for _, p := range []string{
		"src/index.js",
		"server/tools/webhook.ts",
		"SKILL.md",
		"index.ts",
		"hooks/postinstall.sh",
		"mcp.config.json",
		"lib/collect.py",
	} {
		if got := Classify(p); got != Reachable {
			t.Errorf("Classify(%q) = %q, want reachable", p, got)
		}
	}
}

func TestInertNonRuntimePaths(t *testing.T) {
	for _, p := range []string{
		"test/foo.js",
		"tests/foo.js",
		"src/__tests__/a.ts",
		"src/__mocks__/db.ts",
		"examples/demo.sh",
		"example/run.js",
		"fixtures/payload.json",
		"testdata/sample.bin",
		"vendor/pkg/index.js",
		"node_modules/evil/index.js",
		"bench/load.js",
		"pkg/foo_test.go",
		"src/collect.test.ts",
		"src/collect.spec.js",
	} {
		if got := Classify(p); got != Inert {
			t.Errorf("Classify(%q) = %q, want inert", p, got)
		}
	}
}

func TestEmptyPathIsReachable(t *testing.T) {
	// No location info → do not demote; default to reachable so we never hide a
	// finding on a heuristic guess.
	if got := Classify(""); got != Reachable {
		t.Errorf("Classify(\"\") = %q, want reachable", got)
	}
}

func TestWindowsSeparatorsNormalized(t *testing.T) {
	if got := Classify(`src\__tests__\a.ts`); got != Inert {
		t.Errorf("backslash path should classify the same: got %q", got)
	}
}

func TestDocsAndSourceMarkdownStayReachable(t *testing.T) {
	// A skill's payload is often markdown; never demote it by extension.
	for _, p := range []string{"README.md", "agents/SKILL.md", "prompt.md"} {
		if got := Classify(p); got != Reachable {
			t.Errorf("Classify(%q) = %q, want reachable", p, got)
		}
	}
}
