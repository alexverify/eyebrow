package controlplane

import (
	"errors"
	"strings"

	"github.com/alexverify/assay/internal/domain/fleet"
)

// ErrInvalidSnapshot is returned when a submission is missing the org or owner
// identity needed to attribute and aggregate it.
var ErrInvalidSnapshot = errors.New("controlplane: snapshot missing org or owner")

// Service is the control-plane application logic: ingest snapshots and
// aggregate them. It reuses the pure fleet functions verbatim, so a hosted
// report is identical to what the same snapshots produce locally.
type Service struct {
	store Store
}

// NewService wires the service to a store.
func NewService(store Store) *Service { return &Service{store: store} }

// Submit validates and persists one machine's snapshot under an org. The
// snapshot is content-free by construction (fleet.Snapshot carries no bytes);
// Submit only checks it is attributable.
func (s *Service) Submit(org string, snap fleet.Snapshot) error {
	if strings.TrimSpace(org) == "" || strings.TrimSpace(snap.Owner) == "" {
		return ErrInvalidSnapshot
	}
	return s.store.PutSnapshot(org, snap)
}

// Fleet aggregates an org's stored snapshots into the blast-radius report, the
// same shape the local dashboard renders.
func (s *Service) Fleet(org string) (fleet.Report, error) {
	snaps, err := s.store.Snapshots(org)
	if err != nil {
		return fleet.Report{}, err
	}
	return fleet.Aggregate(snaps), nil
}
