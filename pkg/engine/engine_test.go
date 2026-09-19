package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/pkg/engine"
)

func fixedClock() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) }

func TestScanFindsTheSkillAndPasses(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock, Generator: "engine-test"})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "pass" {
		t.Fatalf("verdict %q, want pass; violations %+v", rep.Verdict, rep.Policy.Violations)
	}
	if len(rep.Artifacts) != 1 {
		t.Fatalf("artifacts: %+v", rep.Artifacts)
	}
	a := rep.Artifacts[0]
	if a.Type != "skill" || a.Name != "deploy-helper" || a.Tool != "claude-code" {
		t.Fatalf("unexpected artifact %+v", a)
	}
	if a.Digest == "" {
		t.Fatal("digest missing")
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"findings":[]`) {
		t.Fatalf("expected empty findings to serialise as [], not null: %s", b)
	}
}

func TestScanFailsOnACriticalFinding(t *testing.T) {
	root := writeFixture(t, true)
	e := engine.New(engine.Options{Clock: fixedClock, Generator: "engine-test"})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "fail" {
		t.Fatalf("verdict %q, want fail", rep.Verdict)
	}
	var hit bool
	for _, f := range rep.Findings {
		if f.RuleID == "RCE-PIPE-EXEC" && f.Artifact == "deploy-helper" && f.File == "SKILL.md" && f.Line > 0 {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("RCE-PIPE-EXEC not reported: %+v", rep.Findings)
	}
	if len(rep.Policy.Violations) == 0 || rep.Policy.Violations[0].Kind != "finding" {
		t.Fatalf("expected a finding violation, got %+v", rep.Policy.Violations)
	}
}

func TestScanLockfileRoundTripsThroughTheCLIStore(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock, Generator: "engine-test"})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "eyebrowlock.json")
	if err := os.WriteFile(path, rep.Lockfile, 0o644); err != nil {
		t.Fatal(err)
	}
	lf, err := lockstore.New().Read(context.Background(), path)
	if err != nil {
		t.Fatalf("CLI store cannot read the engine lockfile: %v", err)
	}
	again, err := lockstore.Marshal(lf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, rep.Lockfile) {
		t.Fatalf("lockfile bytes are not stable through the CLI store\nengine: %s\nstore: %s", rep.Lockfile, again)
	}
	if lf.Generator != "engine-test" || !lf.GeneratedAt.Equal(fixedClock()) {
		t.Fatalf("generator or clock not honoured: %+v", lf)
	}
}

func TestScanHonoursAnInlinePolicy(t *testing.T) {
	root := writeFixture(t, true)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{
		Root:   root,
		Policy: []byte(`{"ignoreRules":["RCE-PIPE-EXEC"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "pass" {
		t.Fatalf("ignored rule must not fail the scan; violations %+v", rep.Policy.Violations)
	}
}

func TestScanRejectsABadPolicy(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{})
	_, err := e.Scan(context.Background(), engine.ScanRequest{Root: root, Policy: []byte(`{`)})
	if err == nil {
		t.Fatal("expected an error for malformed policy JSON")
	}
}

func TestVerifyIsCleanOnAnUnchangedTree(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.Verify(context.Background(), engine.VerifyRequest{Root: root, Expected: rep.Lockfile})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "clean" || v.Verdict != "pass" || len(v.Changes) != 0 {
		t.Fatalf("expected clean/pass, got %+v", v)
	}
}

func TestVerifyReportsContentDrift(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(root, ".claude", "skills", "deploy-helper", "SKILL.md")
	if err := os.WriteFile(skill, []byte("---\nname: deploy-helper\n---\nchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := e.Verify(context.Background(), engine.VerifyRequest{Root: root, Expected: rep.Lockfile})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "drift" || v.Verdict != "fail" {
		t.Fatalf("expected drift/fail, got %+v", v)
	}
	if len(v.Changes) != 1 || v.Changes[0].Kind != "content_changed" || v.Changes[0].Name != "deploy-helper" {
		t.Fatalf("unexpected changes %+v", v.Changes)
	}
	if v.Changes[0].Old == "" || v.Changes[0].New == "" || v.Changes[0].Old == v.Changes[0].New {
		t.Fatalf("old and new digests must differ: %+v", v.Changes[0])
	}
}

func TestVerifyAllowContentDriftPassesButStillReports(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(root, ".claude", "skills", "deploy-helper", "SKILL.md")
	if err := os.WriteFile(skill, []byte("---\nname: deploy-helper\n---\nchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := e.Verify(context.Background(), engine.VerifyRequest{
		Root: root, Expected: rep.Lockfile, Policy: []byte(`{"allowContentDrift":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "drift" || v.Verdict != "pass" {
		t.Fatalf("expected drift/pass, got %+v", v)
	}
}

func TestVerifyRejectsMalformedExpected(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{})
	_, err := e.Verify(context.Background(), engine.VerifyRequest{Root: root, Expected: []byte("nope")})
	if err == nil {
		t.Fatal("expected an error for malformed lockfile JSON")
	}
}

func TestScanRejectsAMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	e := engine.New(engine.Options{})
	_, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

func TestScanAcceptsAnEmptyRoot(t *testing.T) {
	root := t.TempDir()
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Artifacts) != 0 {
		t.Fatalf("artifacts: %+v", rep.Artifacts)
	}
	if rep.Verdict != "pass" {
		t.Fatalf("verdict %q, want pass", rep.Verdict)
	}
}

func TestVerifyRejectsAMissingRoot(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err = e.Verify(context.Background(), engine.VerifyRequest{Root: missing, Expected: rep.Lockfile})
	if err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

func TestScanIgnoresApprovalRules(t *testing.T) {
	root := writeFixture(t, false)
	e := engine.New(engine.Options{Clock: fixedClock})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{
		Root:   root,
		Policy: []byte(`{"requireApproval":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "pass" {
		t.Fatalf("verdict %q, want pass; violations %+v", rep.Verdict, rep.Policy.Violations)
	}
	if len(rep.Policy.Violations) != 0 {
		t.Fatalf("expected no violations, got %+v", rep.Policy.Violations)
	}
}

func TestOfflineEngineDoesNotResolveRemoteSources(t *testing.T) {
	root := t.TempDir()
	mcpJSON := `{"mcpServers":{"example":{"command":"npx","args":["-y","some-package"]}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(mcpJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.Options{Clock: fixedClock, Offline: true})
	rep, err := e.Scan(context.Background(), engine.ScanRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	var found *engine.Artifact
	for i := range rep.Artifacts {
		if rep.Artifacts[i].Name == "example" {
			found = &rep.Artifacts[i]
		}
	}
	if found == nil {
		t.Fatalf("mcp artifact missing: %+v", rep.Artifacts)
	}
	var hit bool
	for _, f := range found.Findings {
		if f.RuleID == "RESOLVE-UNSUPPORTED" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected an unresolved-source finding rather than a network attempt, got %+v", found.Findings)
	}
}

func TestVerifyIsStableAcrossDirectoriesWithRelativeRoot(t *testing.T) {
	a := writeFixture(t, false)
	b := writeFixture(t, false)

	t.Chdir(a)
	e := engine.New(engine.Options{Clock: fixedClock, Generator: "engine-test"})
	first, err := e.Scan(context.Background(), engine.ScanRequest{Root: "."})
	if err != nil {
		t.Fatal(err)
	}

	t.Chdir(b)
	v, err := e.Verify(context.Background(), engine.VerifyRequest{Root: ".", Expected: first.Lockfile})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "clean" || v.Verdict != "pass" {
		t.Fatalf("expected clean/pass across directories with a relative root, got %+v", v)
	}

	second, err := e.Scan(context.Background(), engine.ScanRequest{Root: "."})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Lockfile, first.Lockfile) {
		t.Fatalf("lockfile is not byte-identical across directories with a relative root\nfirst:  %s\nsecond: %s", first.Lockfile, second.Lockfile)
	}
}
