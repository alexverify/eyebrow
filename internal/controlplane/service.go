package controlplane

import (
	"errors"
	"strings"

	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
)

// ErrInvalidSnapshot is returned when a submission is missing the org or owner
// identity needed to attribute and aggregate it.
var ErrInvalidSnapshot = errors.New("controlplane: snapshot missing org or owner")

// Service is the control-plane application logic: ingest snapshots and
// aggregate them, and serve the admin-set org policy/keys the CLI pulls. It
// reuses the pure fleet functions verbatim, so a hosted report is identical to
// what the same snapshots produce locally.
type Service struct {
	store  Store
	config Config
}

// NewService wires the service to a snapshot store and an org config. config may
// be nil (no policy/keys configured server-side; the CLI stays local).
func NewService(store Store, config Config) *Service {
	return &Service{store: store, config: config}
}

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

// Policy returns the org's configured policy and whether one exists. With no
// config (or no org policy), ok is false and the CLI keeps its local policy.
func (s *Service) Policy(org string) (policy.Policy, bool, error) {
	if s.config == nil {
		return policy.Policy{}, false, nil
	}
	return s.config.Policy(org)
}

// TrustedKeys returns the org's trusted signing keys (empty when unconfigured).
func (s *Service) TrustedKeys(org string) ([]TrustedKey, error) {
	if s.config == nil {
		return nil, nil
	}
	return s.config.TrustedKeys(org)
}
