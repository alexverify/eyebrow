// Package fleet aggregates per-developer inventory snapshots into a team-wide
// blast-radius view (theme G1): "crypto-price-feed just drifted — 3 of 8
// engineers have it installed." It answers "who is exposed" the moment an
// advisory lands, which is impossible to see from a single laptop.
//
// It stays true to the offline-first ethos: a Snapshot is counts-and-hashes
// only — no code, no secrets, no file contents — committed to a shared git path
// or artifact store, exactly like approvals. The dashboard reads whatever
// snapshots it finds and aggregates them; no server is required. This package
// is pure: the caller gathers the snapshots, Aggregate does the math.
package fleet

import (
	"sort"
	"time"
)

// Artifact is the content-free record of one installed artifact: identity and
// content hash, plus the owner's local verdict on it. No code, no secrets.
type Artifact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Hash    string `json:"hash"`
	Drift   string `json:"drift"`   // verified|updated|drifted|new|unsigned
	Verdict string `json:"verdict"` // trusted|review|quarantine
}

// Snapshot is one developer/machine's inventory at a moment. Owner is a
// non-sensitive label (a hostname or a chosen name) — the point is to know who
// is exposed, so it is deliberately identifying, but it carries nothing else.
type Snapshot struct {
	Owner       string     `json:"owner"`
	GeneratedAt time.Time  `json:"generatedAt"`
	Artifacts   []Artifact `json:"artifacts"`
}

// Exposure is one artifact's fleet-wide footprint — its blast radius.
type Exposure struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Owners     []string `json:"owners"`     // who has it, sorted and unique
	Installs   int      `json:"installs"`   // == len(Owners)
	Drifted    int      `json:"drifted"`    // owners on which it is drifted
	Quarantine int      `json:"quarantine"` // owners on which the verdict is quarantine
	Variants   int      `json:"variants"`   // distinct content hashes across the fleet; >1 breaks the monoculture (forks or a rug-pull mid-fleet)
}

// Report is the aggregated fleet picture, exposures sorted most-urgent first.
type Report struct {
	Owners    int        `json:"owners"`    // fleet size (distinct owners)
	Artifacts int        `json:"artifacts"` // distinct artifacts seen
	Exposures []Exposure `json:"exposures"`
	Grid      Grid       `json:"grid"` // artifacts × owners heatmap (G2)
}

// Cell is one square of the heatmap: an owner's state for an artifact. An empty
// Drift means that owner does not have the artifact installed.
type Cell struct {
	Drift   string `json:"drift,omitempty"`   // ""=absent | verified|updated|drifted|new|unsigned
	Verdict string `json:"verdict,omitempty"` // trusted|review|quarantine
}

// GridRow is one artifact across every owner, with cells aligned to Grid.Owners.
type GridRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Cells       []Cell `json:"cells"`
	Installs    int    `json:"installs"`
	Monoculture bool   `json:"monoculture"` // present on every machine — uniform attack surface
	Outlier     bool   `json:"outlier"`     // present on exactly one machine — a lone extension nobody else has
}

// Grid is the artifacts × developers matrix (G2): columns are owners, rows are
// artifacts, cells are colored by drift/verdict. It surfaces monoculture risk
// (a full row everyone runs) and outliers (a near-empty row only one machine has).
type Grid struct {
	Owners []string  `json:"owners"` // columns, sorted
	Rows   []GridRow `json:"rows"`
}

// Aggregate folds snapshots into the blast-radius report. When one owner has
// several snapshots (a re-export), only their most recent counts, so the view
// reflects the current fleet rather than double-counting history.
func Aggregate(snaps []Snapshot) Report {
	latest := latestPerOwner(snaps)

	owners := make([]string, 0, len(latest))
	for o := range latest {
		owners = append(owners, o)
	}
	sort.Strings(owners)

	type acc struct {
		name, kind string
		owners     []string
		drifted    int
		quarantine int
		hashes     map[string]bool
	}
	byID := map[string]*acc{}
	order := []string{} // first-seen order, for deterministic iteration

	for _, owner := range owners {
		for _, a := range latest[owner].Artifacts {
			e := byID[a.ID]
			if e == nil {
				e = &acc{name: a.Name, kind: a.Kind, hashes: map[string]bool{}}
				byID[a.ID] = e
				order = append(order, a.ID)
			}
			e.owners = append(e.owners, owner)
			if a.Hash != "" {
				e.hashes[a.Hash] = true
			}
			if a.Drift == "drifted" {
				e.drifted++
			}
			if a.Verdict == "quarantine" {
				e.quarantine++
			}
		}
	}

	exposures := make([]Exposure, 0, len(order))
	for _, id := range order {
		e := byID[id]
		sort.Strings(e.owners)
		exposures = append(exposures, Exposure{
			ID:         id,
			Name:       e.name,
			Kind:       e.kind,
			Owners:     e.owners,
			Installs:   len(e.owners),
			Drifted:    e.drifted,
			Quarantine: e.quarantine,
			Variants:   len(e.hashes),
		})
	}

	// Most urgent first: risk (drift + quarantine) dominates, then reach
	// (installs), then name for a stable order.
	sort.SliceStable(exposures, func(i, j int) bool {
		ri, rj := exposures[i].Drifted+exposures[i].Quarantine, exposures[j].Drifted+exposures[j].Quarantine
		if ri != rj {
			return ri > rj
		}
		if exposures[i].Installs != exposures[j].Installs {
			return exposures[i].Installs > exposures[j].Installs
		}
		return exposures[i].Name < exposures[j].Name
	})

	return Report{
		Owners:    len(latest),
		Artifacts: len(order),
		Exposures: exposures,
		Grid:      buildGrid(latest, owners),
	}
}

// buildGrid assembles the artifacts × owners heatmap from the deduped snapshots.
// Owners are the sorted columns; each row is an artifact with one cell per owner
// (absent when that owner does not have it). Rows sort by reach (installs) so the
// matrix reads top-down from monoculture to outlier.
func buildGrid(latest map[string]Snapshot, owners []string) Grid {
	// Per owner, index their artifacts by ID for O(1) cell lookup.
	byOwner := make(map[string]map[string]Artifact, len(owners))
	order := []string{}
	meta := map[string]Artifact{} // id → identity (name/kind), first seen
	for _, owner := range owners {
		idx := map[string]Artifact{}
		for _, a := range latest[owner].Artifacts {
			idx[a.ID] = a
			if _, ok := meta[a.ID]; !ok {
				meta[a.ID] = a
				order = append(order, a.ID)
			}
		}
		byOwner[owner] = idx
	}

	rows := make([]GridRow, 0, len(order))
	for _, id := range order {
		cells := make([]Cell, len(owners))
		installs := 0
		for i, owner := range owners {
			if a, ok := byOwner[owner][id]; ok {
				cells[i] = Cell{Drift: a.Drift, Verdict: a.Verdict}
				installs++
			}
		}
		rows = append(rows, GridRow{
			ID:          id,
			Name:        meta[id].Name,
			Kind:        meta[id].Kind,
			Cells:       cells,
			Installs:    installs,
			Monoculture: len(owners) > 1 && installs == len(owners),
			Outlier:     len(owners) > 1 && installs == 1,
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Installs != rows[j].Installs {
			return rows[i].Installs > rows[j].Installs
		}
		return rows[i].Name < rows[j].Name
	})

	return Grid{Owners: owners, Rows: rows}
}

// latestPerOwner keeps each owner's most recent snapshot (by GeneratedAt),
// collapsing re-exports so the fleet reflects current state.
func latestPerOwner(snaps []Snapshot) map[string]Snapshot {
	out := map[string]Snapshot{}
	for _, s := range snaps {
		if s.Owner == "" {
			continue
		}
		if cur, ok := out[s.Owner]; !ok || s.GeneratedAt.After(cur.GeneratedAt) {
			out[s.Owner] = s
		}
	}
	return out
}
