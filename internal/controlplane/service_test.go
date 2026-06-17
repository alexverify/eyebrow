package controlplane

import (
	"testing"

	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
)

func snap(owner string, arts ...fleet.Artifact) fleet.Snapshot {
	return fleet.Snapshot{Owner: owner, Artifacts: arts}
}

func TestSubmitThenFleetAggregates(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	feed := fleet.Artifact{ID: "x", Name: "feed", Kind: "skill", Hash: "h1", Drift: "drifted", Verdict: "review"}
	if err := svc.Submit("acme", snap("alice", feed)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Submit("acme", snap("bob", fleet.Artifact{ID: "x", Name: "feed", Kind: "skill", Hash: "h2", Drift: "verified", Verdict: "trusted"})); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.Fleet("acme")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Owners != 2 || len(rep.Exposures) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if e := rep.Exposures[0]; e.Installs != 2 || e.Drifted != 1 || e.Variants != 2 {
		t.Errorf("blast radius = %+v", e)
	}
}

func TestSubmitReplacesOwnerSnapshot(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "old", Drift: "drifted"}))
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "new", Drift: "verified"}))
	rep, _ := svc.Fleet("acme")
	if rep.Owners != 1 {
		t.Fatalf("a re-submission must not double-count the owner: %+v", rep)
	}
	if rep.Exposures[0].Drifted != 0 {
		t.Errorf("latest snapshot should win (no drift), got %+v", rep.Exposures[0])
	}
}

func TestOrgsAreIsolated(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "h"}))
	svc.Submit("globex", snap("carol", fleet.Artifact{ID: "y", Name: "other", Hash: "h"}))
	rep, _ := svc.Fleet("acme")
	if rep.Owners != 1 || rep.Exposures[0].Name != "feed" {
		t.Errorf("acme must not see globex data: %+v", rep)
	}
}

func TestSubmitRejectsMissingIdentity(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	if err := svc.Submit("", snap("alice")); err == nil {
		t.Error("missing org must be rejected")
	}
	if err := svc.Submit("acme", snap("")); err == nil {
		t.Error("missing owner must be rejected")
	}
}

func TestFleetEmptyOrg(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	rep, err := svc.Fleet("nobody")
	if err != nil || rep.Owners != 0 {
		t.Errorf("an empty org should aggregate to an empty report, got %+v, %v", rep, err)
	}
}

func TestPolicyAndKeysFromConfig(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{RequireApproval: true, Fleet: policy.FleetPolicy{MaxBlastRadius: 2}})
	cfg.SetTrustedKeys("acme", []TrustedKey{{Key: "abc==", Name: "alice"}})
	svc := NewService(NewMemStore(), cfg)

	p, ok, err := svc.Policy("acme")
	if err != nil || !ok {
		t.Fatalf("acme policy should be configured: ok=%v err=%v", ok, err)
	}
	if !p.RequireApproval || p.Fleet.MaxBlastRadius != 2 {
		t.Errorf("policy not served faithfully: %+v", p)
	}
	keys, _ := svc.TrustedKeys("acme")
	if len(keys) != 1 || keys[0].Name != "alice" {
		t.Errorf("keys = %+v", keys)
	}
}

func TestGateOverSubmittedSnapshots(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{Fleet: policy.FleetPolicy{MaxBlastRadius: 1}})
	svc := NewService(NewMemStore(), cfg)
	// Two machines with the same artifact drifted → blast radius 2 > limit 1.
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "h1", Drift: "drifted", Verdict: "review"}))
	svc.Submit("acme", snap("bob", fleet.Artifact{ID: "x", Name: "feed", Hash: "h2", Drift: "drifted", Verdict: "review"}))

	res, err := svc.Gate("acme")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a drift wider than the limit must fail the gate")
	}
	if len(res.BlastBreaches) != 1 || res.BlastBreaches[0].Name != "feed" {
		t.Errorf("breaches = %+v", res.BlastBreaches)
	}
}

func TestIngestAuditAccumulates(t *testing.T) {
	store := NewMemStore()
	svc := NewService(store, nil)
	if err := svc.IngestAudit("acme", []audit.Event{
		{Server: "github", Kind: audit.KindToolCall, Status: audit.StatusOK},
		{Server: "db", Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.IngestAudit("acme", []audit.Event{{Server: "github", Kind: audit.KindToolCall, Status: audit.StatusOK}}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.AuditEvents("acme")
	if len(got) != 3 {
		t.Errorf("expected 3 accumulated events, got %d", len(got))
	}
}

func TestIngestAuditRejectsMissingOrgAndEmptyBatch(t *testing.T) {
	svc := NewService(NewMemStore(), nil)
	if err := svc.IngestAudit("", []audit.Event{{Server: "x", Kind: audit.KindToolCall}}); err == nil {
		t.Error("missing org must be rejected")
	}
	if err := svc.IngestAudit("acme", nil); err != nil {
		t.Errorf("an empty batch should be a harmless no-op, got %v", err)
	}
}

func TestGateCleanFleetPasses(t *testing.T) {
	svc := NewService(NewMemStore(), NewMemConfig())
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "h", Drift: "verified", Verdict: "trusted"}))
	res, err := svc.Gate("acme")
	if err != nil || !res.OK {
		t.Errorf("a clean fleet with no policy should pass: ok=%v err=%v", res.OK, err)
	}
}

func TestUnconfiguredOrgAndNilConfig(t *testing.T) {
	// An org with no policy → not configured (CLI stays local).
	cfg := NewMemConfig()
	svc := NewService(NewMemStore(), cfg)
	if _, ok, _ := svc.Policy("acme"); ok {
		t.Error("an org with no policy must report not-configured")
	}
	// A nil config → never configured, no panic.
	bare := NewService(NewMemStore(), nil)
	if _, ok, _ := bare.Policy("acme"); ok {
		t.Error("nil config must report not-configured")
	}
	if keys, _ := bare.TrustedKeys("acme"); keys != nil {
		t.Errorf("nil config should yield no keys, got %+v", keys)
	}
}
