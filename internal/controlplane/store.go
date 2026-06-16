// Package controlplane is the self-hostable team server (Component 3b, slice
// 4a): it ingests content-free fleet snapshots from each machine and aggregates
// them with the exact pure functions the local dashboard uses (fleet.Aggregate),
// so a team beyond the "git is the backend" scale gets the same blast-radius
// view over the wire. It is strictly opt-in — the CLI works fully offline — and
// it carries only what the offline snapshot already commits: ids, hashes, and
// drift/verdict, never code or secrets.
//
// Storage and transport are injected behind interfaces. This slice ships an
// in-memory store (here) and a file-backed store (internal/adapters/cpstore);
// a Postgres adapter can replace either later for scale without touching the
// service or handlers.
package controlplane

import (
	"sort"
	"sync"

	"github.com/alexverify/assay/internal/domain/fleet"
)

// Store persists each org's fleet snapshots, one per owner (a re-submission
// replaces that owner's prior snapshot, so the view reflects the current fleet,
// mirroring the offline latest-per-owner rule).
type Store interface {
	PutSnapshot(org string, snap fleet.Snapshot) error
	Snapshots(org string) ([]fleet.Snapshot, error)
}

// MemStore is an in-memory Store keyed by org then owner. Safe for concurrent
// use. Used by tests and an ephemeral server; it loses data on restart.
type MemStore struct {
	mu    sync.Mutex
	byOrg map[string]map[string]fleet.Snapshot
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{byOrg: map[string]map[string]fleet.Snapshot{}}
}

// PutSnapshot stores (or replaces) one owner's snapshot under an org.
func (m *MemStore) PutSnapshot(org string, snap fleet.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	owners := m.byOrg[org]
	if owners == nil {
		owners = map[string]fleet.Snapshot{}
		m.byOrg[org] = owners
	}
	owners[snap.Owner] = snap
	return nil
}

// Snapshots returns every owner's latest snapshot for an org, sorted by owner
// for a deterministic order.
func (m *MemStore) Snapshots(org string) ([]fleet.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	owners := m.byOrg[org]
	names := make([]string, 0, len(owners))
	for o := range owners {
		names = append(names, o)
	}
	sort.Strings(names)
	out := make([]fleet.Snapshot, 0, len(names))
	for _, o := range names {
		out = append(out, owners[o])
	}
	return out, nil
}
