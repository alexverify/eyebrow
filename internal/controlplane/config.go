package controlplane

import (
	"sync"

	"github.com/alexverify/assay/internal/domain/policy"
)

// TrustedKey is one publisher signing key the org trusts, mirroring the local
// trusted-keys registry (a base64 ed25519 public key plus an optional label).
type TrustedKey struct {
	Key  string `json:"key"`            // base64-encoded ed25519 public key
	Name string `json:"name,omitempty"` // optional label (who owns it)
}

// Config is the admin-set, read-mostly org configuration the CLI pulls (slice
// 4b): the team policy and the trusted signing keys. It is separate from Store
// (mutable per-machine snapshots) because it is owned by an admin, not produced
// by each machine. A nil Config means nothing is configured server-side — the
// CLI then keeps using its local files.
type Config interface {
	// Policy returns the org's policy and whether one is configured. A false
	// "configured" tells the CLI to fall back to its local policy file.
	Policy(org string) (policy.Policy, bool, error)
	// TrustedKeys returns the org's trusted signing keys (possibly empty).
	TrustedKeys(org string) ([]TrustedKey, error)
}

// MemConfig is an in-memory Config for tests and ephemeral servers.
type MemConfig struct {
	mu   sync.Mutex
	pol  map[string]policy.Policy
	keys map[string][]TrustedKey
}

// NewMemConfig returns an empty in-memory config.
func NewMemConfig() *MemConfig {
	return &MemConfig{pol: map[string]policy.Policy{}, keys: map[string][]TrustedKey{}}
}

// SetPolicy configures an org's policy.
func (m *MemConfig) SetPolicy(org string, p policy.Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pol[org] = p
}

// SetTrustedKeys configures an org's trusted keys.
func (m *MemConfig) SetTrustedKeys(org string, keys []TrustedKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[org] = keys
}

// Policy returns the org's policy, if one was set.
func (m *MemConfig) Policy(org string) (policy.Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pol[org]
	return p, ok, nil
}

// TrustedKeys returns the org's trusted keys.
func (m *MemConfig) TrustedKeys(org string) ([]TrustedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[org], nil
}
