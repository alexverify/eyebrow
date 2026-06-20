package policystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/policy"
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
	path := filepath.Join(dir, "eyebrow.policy.json")
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

func TestSaveRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eyebrow.policy.json")
	want := policy.Policy{
		FailOnSeverity:  finding.SeverityHigh,
		BlockPublishers: []string{"giftshop.club"},
		AllowPublishers: []string{"github.com/myorg"},
		Mutes:           []policy.Mute{{Rule: "EXEC-PRIMITIVE", Reason: "build step", By: "alice"}},
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, present, err := Load(path)
	if err != nil || !present {
		t.Fatalf("Load after Save: present=%v err=%v", present, err)
	}
	if len(got.BlockPublishers) != 1 || got.BlockPublishers[0] != "giftshop.club" {
		t.Errorf("BlockPublishers not round-tripped: %+v", got.BlockPublishers)
	}
	if len(got.AllowPublishers) != 1 || got.AllowPublishers[0] != "github.com/myorg" {
		t.Errorf("AllowPublishers not round-tripped: %+v", got.AllowPublishers)
	}
	if len(got.Mutes) != 1 || got.Mutes[0].Rule != "EXEC-PRIMITIVE" || got.Mutes[0].By != "alice" {
		t.Errorf("Mutes not round-tripped: %+v", got.Mutes)
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
