package fleet

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// gateFixture builds a report+conformance pair from a small fleet for gating.
func gateFixture(t *testing.T, snaps []Snapshot, maxBlast int) GateResult {
	t.Helper()
	rep := Aggregate(snaps)
	// Empty policy → only drift/quarantine drive conformance via the snapshot.
	con := CheckConformance(policy.Policy{}, snaps)
	return Gate(rep, con, maxBlast)
}

func TestGatePassesCleanFleet(t *testing.T) {
	res := gateFixture(t, []Snapshot{
		{Owner: "alice", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h", Drift: "verified", Verdict: "trusted"}}},
		{Owner: "bob", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h", Drift: "verified", Verdict: "trusted"}}},
	}, 0)
	if !res.OK {
		t.Fatalf("a clean, in-policy fleet must pass: %+v", res)
	}
}

func TestGateFailsOnNonCompliantMachine(t *testing.T) {
	// A quarantined artifact still installed makes that machine non-compliant.
	res := gateFixture(t, []Snapshot{
		{Owner: "alice", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h", Drift: "verified", Verdict: "trusted"}}},
		{Owner: "bob", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h2", Drift: "verified", Verdict: "quarantine"}}},
	}, 0)
	if res.OK {
		t.Fatalf("a quarantined install must fail the gate")
	}
	if len(res.NonCompliant) != 1 || res.NonCompliant[0].Owner != "bob" {
		t.Errorf("expected bob flagged non-compliant, got %+v", res.NonCompliant)
	}
}

func TestGateFailsOnWideBlastRadius(t *testing.T) {
	// A drifted artifact on 2 machines, threshold 1 → breach.
	snaps := []Snapshot{
		{Owner: "alice", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h1", Drift: "drifted", Verdict: "review"}}},
		{Owner: "bob", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h2", Drift: "drifted", Verdict: "review"}}},
	}
	res := gateFixture(t, snaps, 1)
	if res.OK {
		t.Fatalf("a drift on more machines than the threshold must fail")
	}
	if len(res.BlastBreaches) != 1 || res.BlastBreaches[0].ID != "x" {
		t.Errorf("expected the feed exposure flagged, got %+v", res.BlastBreaches)
	}
}

func TestGateBlastCheckDisabledAtZeroThreshold(t *testing.T) {
	// maxBlast <= 0 disables the reach check; a wide drift alone does not fail.
	snaps := []Snapshot{
		{Owner: "alice", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h1", Drift: "drifted", Verdict: "review"}}},
		{Owner: "bob", Artifacts: []Artifact{{ID: "x", Name: "feed", Hash: "h2", Drift: "drifted", Verdict: "review"}}},
	}
	res := gateFixture(t, snaps, 0)
	if !res.OK {
		t.Errorf("with the reach check off and no policy violation, the gate should pass: %+v", res)
	}
}
