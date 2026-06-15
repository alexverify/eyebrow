package fleetstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/assay/internal/domain/fleet"
)

func TestWriteThenReadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	snap := fleet.Snapshot{
		Owner:       "alice",
		GeneratedAt: time.Unix(1000, 0).UTC(),
		Artifacts:   []fleet.Artifact{{ID: "x", Name: "feed", Kind: "skill", Hash: "h", Drift: "drifted", Verdict: "quarantine"}},
	}
	if err := Write(dir, snap); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got[0].Owner != "alice" || len(got[0].Artifacts) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got[0].Artifacts[0].Drift != "drifted" {
		t.Errorf("artifact field lost: %+v", got[0].Artifacts[0])
	}
}

func TestReadMissingDirIsEmpty(t *testing.T) {
	got, err := Read(filepath.Join(t.TempDir(), "nope"))
	if err != nil || got != nil {
		t.Errorf("missing dir should be (nil, nil), got (%v, %v)", got, err)
	}
}

func TestReadSkipsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, fleet.Snapshot{Owner: "ok", Artifacts: nil}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got[0].Owner != "ok" {
		t.Errorf("corrupt file should be skipped, the rest kept: %+v", got)
	}
}

func TestWriteSanitizesOwnerName(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, fleet.Snapshot{Owner: "../../etc/passwd"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("want exactly one file in the fleet dir, got %d", len(entries))
	}
	if name := entries[0].Name(); filepath.Dir(name) != "." {
		t.Errorf("owner name escaped the directory: %q", name)
	}
}
