package cpstore

import (
	"path/filepath"
	"testing"

	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/fleet"
)

// compile-time check: the file store satisfies the control-plane Store port.
var _ controlplane.Store = (*Store)(nil)

func TestPersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice",
		Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Hash: "h", Drift: "drifted"}}}); err != nil {
		t.Fatal(err)
	}
	// A fresh Store over the same dir sees the persisted snapshot (server restart).
	got, err := New(dir).Snapshots("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Owner != "alice" {
		t.Fatalf("did not persist: %+v", got)
	}
}

func TestReplaceOwnerSnapshot(t *testing.T) {
	s := New(t.TempDir())
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "x", Hash: "old"}}})
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "x", Hash: "new"}}})
	got, _ := s.Snapshots("acme")
	if len(got) != 1 || got[0].Artifacts[0].Hash != "new" {
		t.Errorf("re-submission should replace, got %+v", got)
	}
}

func TestOrgsIsolatedOnDisk(t *testing.T) {
	s := New(t.TempDir())
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "x"}}})
	s.PutSnapshot("globex", fleet.Snapshot{Owner: "carol", Artifacts: []fleet.Artifact{{ID: "y"}}})
	acme, _ := s.Snapshots("acme")
	if len(acme) != 1 || acme[0].Owner != "alice" {
		t.Errorf("orgs must be isolated, got %+v", acme)
	}
}

func TestMissingOrgIsEmpty(t *testing.T) {
	got, err := New(t.TempDir()).Snapshots("nobody")
	if err != nil || got != nil {
		t.Errorf("missing org should be nil,nil; got %+v, %v", got, err)
	}
}

func TestOwnerCannotEscapeDir(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.PutSnapshot("acme", fleet.Snapshot{Owner: "../../etc/passwd",
		Artifacts: []fleet.Artifact{{ID: "x"}}}); err != nil {
		t.Fatal(err)
	}
	// The sanitized file stays inside the org dir.
	got, _ := s.Snapshots("acme")
	if len(got) != 1 {
		t.Fatalf("expected the sanitized snapshot back, got %+v", got)
	}
	if _, err := filepath.Glob(filepath.Join(dir, "acme", "*.json")); err != nil {
		t.Fatal(err)
	}
}
