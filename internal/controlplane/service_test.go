package controlplane

import (
	"testing"

	"github.com/alexverify/assay/internal/domain/fleet"
)

func snap(owner string, arts ...fleet.Artifact) fleet.Snapshot {
	return fleet.Snapshot{Owner: owner, Artifacts: arts}
}

func TestSubmitThenFleetAggregates(t *testing.T) {
	svc := NewService(NewMemStore())
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
	svc := NewService(NewMemStore())
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
	svc := NewService(NewMemStore())
	svc.Submit("acme", snap("alice", fleet.Artifact{ID: "x", Name: "feed", Hash: "h"}))
	svc.Submit("globex", snap("carol", fleet.Artifact{ID: "y", Name: "other", Hash: "h"}))
	rep, _ := svc.Fleet("acme")
	if rep.Owners != 1 || rep.Exposures[0].Name != "feed" {
		t.Errorf("acme must not see globex data: %+v", rep)
	}
}

func TestSubmitRejectsMissingIdentity(t *testing.T) {
	svc := NewService(NewMemStore())
	if err := svc.Submit("", snap("alice")); err == nil {
		t.Error("missing org must be rejected")
	}
	if err := svc.Submit("acme", snap("")); err == nil {
		t.Error("missing owner must be rejected")
	}
}

func TestFleetEmptyOrg(t *testing.T) {
	svc := NewService(NewMemStore())
	rep, err := svc.Fleet("nobody")
	if err != nil || rep.Owners != 0 {
		t.Errorf("an empty org should aggregate to an empty report, got %+v, %v", rep, err)
	}
}
