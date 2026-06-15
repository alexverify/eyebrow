package fleet

import (
	"testing"
	"time"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func exposure(t *testing.T, r Report, id string) Exposure {
	t.Helper()
	for _, e := range r.Exposures {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no exposure for %q in %+v", id, r.Exposures)
	return Exposure{}
}

func TestAggregateBlastRadius(t *testing.T) {
	snaps := []Snapshot{
		{Owner: "carol", GeneratedAt: ts("2026-06-10T00:00:00Z"), Artifacts: []Artifact{
			{ID: "x", Name: "crypto-price-feed", Kind: "skill", Hash: "h1", Drift: "verified", Verdict: "trusted"},
		}},
		{Owner: "alice", GeneratedAt: ts("2026-06-10T00:00:00Z"), Artifacts: []Artifact{
			{ID: "x", Name: "crypto-price-feed", Kind: "skill", Hash: "h2", Drift: "drifted", Verdict: "quarantine"},
		}},
		{Owner: "bob", GeneratedAt: ts("2026-06-10T00:00:00Z"), Artifacts: []Artifact{
			{ID: "y", Name: "linter", Kind: "skill", Hash: "h9", Drift: "verified", Verdict: "trusted"},
		}},
	}
	r := Aggregate(snaps)

	if r.Owners != 3 {
		t.Errorf("fleet size = %d, want 3", r.Owners)
	}
	if r.Artifacts != 2 {
		t.Errorf("distinct artifacts = %d, want 2", r.Artifacts)
	}
	x := exposure(t, r, "x")
	if x.Installs != 2 {
		t.Errorf("crypto-price-feed installs = %d, want 2", x.Installs)
	}
	if x.Drifted != 1 || x.Quarantine != 1 {
		t.Errorf("x drifted=%d quarantine=%d, want 1/1", x.Drifted, x.Quarantine)
	}
	if x.Variants != 2 {
		t.Errorf("x variants = %d, want 2 (two distinct hashes)", x.Variants)
	}
	wantOwners := []string{"alice", "carol"}
	if len(x.Owners) != 2 || x.Owners[0] != wantOwners[0] || x.Owners[1] != wantOwners[1] {
		t.Errorf("x owners = %v, want sorted %v", x.Owners, wantOwners)
	}
}

func TestAggregateDedupsOwnerKeepingLatest(t *testing.T) {
	// The same owner re-exports; only the latest snapshot counts.
	snaps := []Snapshot{
		{Owner: "alice", GeneratedAt: ts("2026-06-01T00:00:00Z"), Artifacts: []Artifact{
			{ID: "x", Name: "feed", Kind: "skill", Hash: "old", Drift: "verified", Verdict: "trusted"},
		}},
		{Owner: "alice", GeneratedAt: ts("2026-06-10T00:00:00Z"), Artifacts: []Artifact{
			{ID: "x", Name: "feed", Kind: "skill", Hash: "new", Drift: "drifted", Verdict: "quarantine"},
		}},
	}
	r := Aggregate(snaps)
	if r.Owners != 1 {
		t.Errorf("a re-exporting owner must count once, got %d", r.Owners)
	}
	x := exposure(t, r, "x")
	if x.Installs != 1 {
		t.Errorf("installs = %d, want 1", x.Installs)
	}
	if x.Drifted != 1 {
		t.Errorf("latest snapshot (drifted) should win, got drifted=%d", x.Drifted)
	}
	if x.Variants != 1 {
		t.Errorf("variants = %d, want 1 (stale hash dropped)", x.Variants)
	}
}

func TestAggregateSortsRiskThenReach(t *testing.T) {
	// A drifted artifact on one machine must rank above a clean artifact on many.
	snaps := []Snapshot{
		{Owner: "a", Artifacts: []Artifact{
			{ID: "risky", Name: "risky", Kind: "mcp", Hash: "h", Drift: "drifted", Verdict: "quarantine"},
			{ID: "common", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
		{Owner: "b", Artifacts: []Artifact{
			{ID: "common", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
		{Owner: "c", Artifacts: []Artifact{
			{ID: "common", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
	}
	r := Aggregate(snaps)
	if r.Exposures[0].ID != "risky" {
		t.Errorf("risk should sort first; got order %v", ids(r.Exposures))
	}
}

func TestAggregateEmpty(t *testing.T) {
	r := Aggregate(nil)
	if r.Owners != 0 || len(r.Exposures) != 0 {
		t.Errorf("empty fleet should be zero, got %+v", r)
	}
}

func ids(es []Exposure) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}
