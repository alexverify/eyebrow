package controlplane

import (
	"errors"
	"strings"

	"github.com/alexverify/assay/internal/domain/alert"
	"github.com/alexverify/assay/internal/domain/audit"
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

// IngestAudit appends a batch of audit events to the org's log. The events are
// content-free by construction (arguments are digested, secrets redacted at the
// shim); IngestAudit only checks the org is attributable and drops empty batches.
func (s *Service) IngestAudit(org string, events []audit.Event) error {
	if strings.TrimSpace(org) == "" {
		return ErrInvalidSnapshot
	}
	if len(events) == 0 {
		return nil
	}
	return s.store.AppendAudit(org, events)
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

// Alerts derives the org's team-level alerts (Phase 4d) from its aggregated
// fleet and ingested audit events — drift, quarantine, blocked egress, denied
// tool calls — most urgent first.
func (s *Service) Alerts(org string) ([]alert.Alert, error) {
	snaps, err := s.store.Snapshots(org)
	if err != nil {
		return nil, err
	}
	events, err := s.store.AuditEvents(org)
	if err != nil {
		return nil, err
	}
	return alert.Derive(fleet.Aggregate(snaps), events), nil
}

// Gate runs the fleet CI gate (Phase 3) server-side over the org's submitted
// snapshots and configured policy — the hosted equivalent of `assay fleet
// verify`. It reuses the exact pure functions, so a CI failure here matches what
// a teammate sees locally. With no org policy configured, the default policy
// applies (blast-radius check off; only quarantine flags conformance).
func (s *Service) Gate(org string) (fleet.GateResult, error) {
	snaps, err := s.store.Snapshots(org)
	if err != nil {
		return fleet.GateResult{}, err
	}
	pol, ok, err := s.Policy(org)
	if err != nil {
		return fleet.GateResult{}, err
	}
	if !ok {
		pol = policy.Default()
	}
	rep := fleet.Aggregate(snaps)
	con := fleet.CheckConformance(pol, snaps)
	return fleet.Gate(rep, con, pol.Fleet.MaxBlastRadius), nil
}
