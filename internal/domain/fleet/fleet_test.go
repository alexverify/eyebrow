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

func gridRow(t *testing.T, g Grid, id string) GridRow {
	t.Helper()
	for _, r := range g.Rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no grid row for %q", id)
	return GridRow{}
}

func TestGridCellsAlignToOwners(t *testing.T) {
	snaps := []Snapshot{
		{Owner: "bob", Artifacts: []Artifact{
			{ID: "x", Name: "feed", Kind: "skill", Hash: "h", Drift: "drifted", Verdict: "quarantine"},
		}},
		{Owner: "alice", Artifacts: []Artifact{
			{ID: "x", Name: "feed", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
			{ID: "y", Name: "linter", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
	}
	g := Aggregate(snaps).Grid

	if len(g.Owners) != 2 || g.Owners[0] != "alice" || g.Owners[1] != "bob" {
		t.Fatalf("owners columns = %v, want sorted [alice bob]", g.Owners)
	}
	x := gridRow(t, g, "x")
	// Column 0 = alice (verified), column 1 = bob (drifted).
	if x.Cells[0].Drift != "verified" || x.Cells[1].Drift != "drifted" {
		t.Errorf("x cells misaligned with owners: %+v", x.Cells)
	}
	// y exists only for alice → bob's cell is absent (empty drift).
	y := gridRow(t, g, "y")
	if y.Cells[0].Drift != "verified" || y.Cells[1].Drift != "" {
		t.Errorf("y should be present for alice, absent for bob: %+v", y.Cells)
	}
}

func TestGridMonocultureAndOutlier(t *testing.T) {
	snaps := []Snapshot{
		{Owner: "a", Artifacts: []Artifact{
			{ID: "everywhere", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
			{ID: "lonely", Name: "weird", Kind: "hook", Hash: "h", Drift: "new", Verdict: "review"},
		}},
		{Owner: "b", Artifacts: []Artifact{
			{ID: "everywhere", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
		{Owner: "c", Artifacts: []Artifact{
			{ID: "everywhere", Name: "common", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"},
		}},
	}
	g := Aggregate(snaps).Grid

	if !gridRow(t, g, "everywhere").Monoculture {
		t.Errorf("an artifact on every machine should be flagged monoculture")
	}
	if !gridRow(t, g, "lonely").Outlier {
		t.Errorf("an artifact on exactly one machine should be flagged outlier")
	}
	// Rows sort by reach: the monoculture leads.
	if g.Rows[0].ID != "everywhere" {
		t.Errorf("rows should sort by reach; got %v", func() []string {
			out := make([]string, len(g.Rows))
			for i, r := range g.Rows {
				out[i] = r.ID
			}
			return out
		}())
	}
}

func TestGridSingleOwnerHasNoMonoculture(t *testing.T) {
	// With one machine, "everyone has it" is meaningless — never flag it.
	g := Aggregate([]Snapshot{
		{Owner: "solo", Artifacts: []Artifact{{ID: "x", Name: "feed", Kind: "skill", Hash: "h", Drift: "verified", Verdict: "trusted"}}},
	}).Grid
	r := gridRow(t, g, "x")
	if r.Monoculture || r.Outlier {
		t.Errorf("single-owner fleet should flag neither: %+v", r)
	}
}

func ids(es []Exposure) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}
