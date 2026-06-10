package policystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/agentguard/internal/domain/finding"
)

func TestLoadMissingReturnsDefault(t *testing.T) {
	p, present, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if present {
		t.Error("present should be false for a missing file")
	}
	if p.FailOnSeverity != finding.SeverityHigh {
		t.Errorf("default FailOnSeverity = %q, want high", p.FailOnSeverity)
	}
}

func TestLoadParsesAndNormalizes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentguard.policy.json")
	if err := os.WriteFile(path, []byte(`{"ignoreRules":["EXEC-PRIMITIVE"],"requireApproval":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, present, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !present {
		t.Error("present should be true")
	}
	if !p.RequireApproval || len(p.IgnoreRules) != 1 || p.IgnoreRules[0] != "EXEC-PRIMITIVE" {
		t.Errorf("fields not parsed: %+v", p)
	}
	// Unspecified threshold normalizes to high.
	if p.FailOnSeverity != finding.SeverityHigh {
		t.Errorf("FailOnSeverity should default to high, got %q", p.FailOnSeverity)
	}
}

func TestLoadMalformedErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("malformed policy must error")
	}
}
