// Package cpstore is a file-backed store for the control-plane server. Per org
// (<dir>/<org>/): one snapshot per owner under snapshots/<owner>.json, plus the
// admin-set policy.json and trustedkeys.json. It is the zero-dependency default
// persistence for a self-hosted `assay serve`, in the same spirit as the rest
// of assay's "files are the backend" storage. It structurally satisfies both
// controlplane.Store and controlplane.Config; a Postgres adapter can replace it
// for scale without touching the service or handlers.
package cpstore

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
	"github.com/alexverify/assay/internal/domain/reputation"
)

const (
	snapshotsSubdir = "snapshots"
	policyFile      = "policy.json"
	keysFile        = "trustedkeys.json"
	auditFile       = "audit.jsonl"
	reputationFile  = "reputation.json"
)

// Store roots a file store at a directory.
type Store struct{ dir string }

// New returns a Store rooted at dir (created on first write).
func New(dir string) *Store { return &Store{dir: dir} }

// PutSnapshot writes (or replaces) one owner's snapshot under an org. The owner
// and org are sanitized into safe path segments so neither can escape the store.
func (s *Store) PutSnapshot(org string, snap fleet.Snapshot) error {
	snapDir := filepath.Join(s.dir, safeName(org), snapshotsSubdir)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(snapDir, safeName(snap.Owner)+".json"), append(b, '\n'), 0o644)
}

// Snapshots returns every owner's snapshot for an org, sorted by file name. A
// missing org directory yields no snapshots and no error; a corrupt or
// ownerless file is skipped so one bad submission never hides the rest.
func (s *Store) Snapshots(org string) ([]fleet.Snapshot, error) {
	snapDir := filepath.Join(s.dir, safeName(org), snapshotsSubdir)
	entries, err := os.ReadDir(snapDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		names = append(names, ent.Name())
	}
	sort.Strings(names)

	var out []fleet.Snapshot
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(snapDir, name))
		if err != nil {
			return nil, err
		}
		var snap fleet.Snapshot
		if json.Unmarshal(b, &snap) != nil || snap.Owner == "" {
			continue
		}
		out = append(out, snap)
	}
	return out, nil
}

// AppendAudit appends ingested audit events to the org's JSONL log, one event
// per line (matching the local audit-log format).
func (s *Store) AppendAudit(org string, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	orgDir := filepath.Join(s.dir, safeName(org))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(orgDir, auditFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// AuditEvents reads back the org's ingested audit events. A missing log yields
// none; a corrupt line is skipped so one bad event never hides the rest.
func (s *Store) AuditEvents(org string) ([]audit.Event, error) {
	f, err := os.Open(filepath.Join(s.dir, safeName(org), auditFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e audit.Event
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// PutReputation writes an org's reputation corpus.
func (s *Store) PutReputation(org string, src reputation.Source) error {
	orgDir := filepath.Join(s.dir, safeName(org))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(orgDir, reputationFile), append(b, '\n'), 0o644)
}

// Reputation returns the org's hash-keyed reputation corpus (nil when absent).
func (s *Store) Reputation(org string) (reputation.Source, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, safeName(org), reputationFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var src reputation.Source
	if err := json.Unmarshal(b, &src); err != nil {
		return nil, err
	}
	return src, nil
}

// PutPolicy writes an org's policy (the admin-set config the CLI pulls).
func (s *Store) PutPolicy(org string, p policy.Policy) error {
	orgDir := filepath.Join(s.dir, safeName(org))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(orgDir, policyFile), append(b, '\n'), 0o644)
}

// Policy returns the org's configured policy. A missing file means "not
// configured" (ok=false), so the CLI keeps its local policy.
func (s *Store) Policy(org string) (policy.Policy, bool, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, safeName(org), policyFile))
	if os.IsNotExist(err) {
		return policy.Policy{}, false, nil
	}
	if err != nil {
		return policy.Policy{}, false, err
	}
	var p policy.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return policy.Policy{}, false, err
	}
	return p, true, nil
}

// PutTrustedKeys writes an org's trusted signing keys.
func (s *Store) PutTrustedKeys(org string, keys []controlplane.TrustedKey) error {
	orgDir := filepath.Join(s.dir, safeName(org))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(orgDir, keysFile), append(b, '\n'), 0o644)
}

// TrustedKeys returns the org's trusted signing keys (nil when unconfigured).
func (s *Store) TrustedKeys(org string) ([]controlplane.TrustedKey, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, safeName(org), keysFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []controlplane.TrustedKey
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// safeName reduces a label to a filesystem-safe slug so it cannot escape the
// store directory, mirroring fleetstore's sanitizing.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "default"
	}
	return out
}
