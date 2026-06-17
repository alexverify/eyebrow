package cpstore

import (
	"path/filepath"
	"testing"

	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
)

// compile-time checks: the file store satisfies both control-plane ports.
var (
	_ controlplane.Store  = (*Store)(nil)
	_ controlplane.Config = (*Store)(nil)
)

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
	// The sanitized file stays inside the org's snapshots dir.
	got, _ := s.Snapshots("acme")
	if len(got) != 1 {
		t.Fatalf("expected the sanitized snapshot back, got %+v", got)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "acme", "snapshots", "*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("sanitized snapshot should live in the org snapshots dir: %v %v", matches, err)
	}
}

func TestAuditAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if got, _ := s.AuditEvents("acme"); got != nil {
		t.Fatal("no audit yet should be nil")
	}
	if err := s.AppendAudit("acme", []audit.Event{
		{Server: "github", Kind: audit.KindToolCall, Status: audit.StatusOK},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit("acme", []audit.Event{
		{Server: "db", Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := New(dir).AuditEvents("acme") // fresh instance: persisted across restart
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Server != "github" || got[1].Host != "evil.example" {
		t.Errorf("audit round-trip = %+v", got)
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	if _, ok, _ := s.Policy("acme"); ok {
		t.Fatal("unconfigured org must report no policy")
	}
	want := policy.Policy{RequireApproval: true, Fleet: policy.FleetPolicy{MaxBlastRadius: 3}}
	if err := s.PutPolicy("acme", want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := New(s.dir).Policy("acme") // fresh instance: persisted
	if err != nil || !ok {
		t.Fatalf("policy should persist: ok=%v err=%v", ok, err)
	}
	if !got.RequireApproval || got.Fleet.MaxBlastRadius != 3 {
		t.Errorf("policy = %+v", got)
	}
}

func TestTrustedKeysRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	if keys, _ := s.TrustedKeys("acme"); keys != nil {
		t.Fatal("unconfigured org must report no keys")
	}
	want := []controlplane.TrustedKey{{Key: "AAAA==", Name: "alice"}, {Key: "BBBB=="}}
	if err := s.PutTrustedKeys("acme", want); err != nil {
		t.Fatal(err)
	}
	got, err := New(s.dir).TrustedKeys("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alice" || got[1].Key != "BBBB==" {
		t.Errorf("keys = %+v", got)
	}
}

func TestPolicyAndSnapshotsCoexist(t *testing.T) {
	// An owner literally named "policy" must not collide with policy.json.
	s := New(t.TempDir())
	s.PutPolicy("acme", policy.Policy{RequireApproval: true})
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "policy", Artifacts: []fleet.Artifact{{ID: "x"}}})
	if _, ok, _ := s.Policy("acme"); !ok {
		t.Error("policy must survive a snapshot owned by 'policy'")
	}
	got, _ := s.Snapshots("acme")
	if len(got) != 1 || got[0].Owner != "policy" {
		t.Errorf("snapshot owned by 'policy' must coexist with policy.json: %+v", got)
	}
}
