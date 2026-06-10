// Package lockfile defines the agentlock.json model and the drift-detection
// logic that powers `agentguard verify` — the rug-pull detector.
//
// Like the rest of the domain core, this package is pure: Build assembles a
// deterministic snapshot from artifacts, and Compare diffs two snapshots with
// no IO. Reading and writing the file lives in the lockstore adapter.
package lockfile

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
)

// CanonicalBytes returns the deterministic serialization of the lockfile used
// for signing: the same content with the signature field cleared, so a
// signature commits to everything except itself. Entries are already sorted by
// Build, and JSON marshals map keys in order, so the output is stable.
func CanonicalBytes(lf Lockfile) ([]byte, error) {
	lf.Sig = ""
	return json.Marshal(lf)
}

// Version is the current agentlock.json schema version.
const Version = 1

// Approval records a human (optionally signed) sign-off on an artifact's
// current content. verify --ci can require approval before allowing a build.
type Approval struct {
	Status string    `json:"status"` // "approved" | "pending" | "rejected"
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitempty"`
	Sig    string    `json:"sig,omitempty"` // ed25519:… over the artifact ContentHash
}

// Entry is one artifact as recorded in the lockfile, with its approval state.
// The artifact fields are flattened into the JSON object.
type Entry struct {
	artifact.Artifact
	Approval *Approval `json:"approval,omitempty"`
}

// Lockfile is the committed, signable, human-diffable snapshot of an inventory.
type Lockfile struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	Generator   string    `json:"generator"`
	Artifacts   []Entry   `json:"artifacts"`
	Sig         string    `json:"lockfileSig,omitempty"` // ed25519 over the canonical body
}

// Build assembles a deterministic Lockfile from discovered artifacts. Entries
// are sorted by ID so the serialized file is stable across runs and produces
// minimal diffs in version control.
func Build(arts []artifact.Artifact, generatedAt time.Time, generator string) Lockfile {
	entries := make([]Entry, 0, len(arts))
	for _, a := range arts {
		entries = append(entries, Entry{Artifact: a})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return Lockfile{
		Version:     Version,
		GeneratedAt: generatedAt,
		Generator:   generator,
		Artifacts:   entries,
	}
}

// byID indexes entries for comparison.
func (l Lockfile) byID() map[string]Entry {
	m := make(map[string]Entry, len(l.Artifacts))
	for _, e := range l.Artifacts {
		m[e.ID] = e
	}
	return m
}

// HasFindingAtLeast reports whether any artifact carries a finding of at least
// the given severity.
func (l Lockfile) HasFindingAtLeast(min finding.Severity) bool {
	for _, e := range l.Artifacts {
		for _, f := range e.Findings {
			if f.Severity.AtLeast(min) {
				return true
			}
		}
	}
	return false
}

// DriftKind classifies a single change between a locked and a current snapshot.
type DriftKind string

const (
	DriftAdded            DriftKind = "added"             // present now, absent before
	DriftRemoved          DriftKind = "removed"           // present before, absent now
	DriftContentChanged   DriftKind = "content_changed"   // ContentHash moved (classic rug pull)
	DriftVersionChanged   DriftKind = "version_changed"   // pinned source ref changed
	DriftIntegrityChanged DriftKind = "integrity_changed" // npm integrity changed
	DriftCertRotated      DriftKind = "cert_rotated"      // remote TLS SPKI pin changed
)

// Change is one detected difference. Old/New hold the relevant values for the
// kind (e.g. the two content hashes), empty where not applicable.
type Change struct {
	Kind DriftKind `json:"kind"`
	ID   string    `json:"id"`
	Name string    `json:"name"`
	Old  string    `json:"old,omitempty"`
	New  string    `json:"new,omitempty"`
}

// Diff is the full set of changes between two snapshots.
type Diff struct {
	Changes []Change `json:"changes"`
}

// HasDrift reports whether any change was detected.
func (d Diff) HasDrift() bool { return len(d.Changes) > 0 }

// Compare diffs a locked snapshot against the current one, matching artifacts
// by stable ID. The result is deterministically ordered. This is the core of
// the rug-pull detector: a moved content hash, a changed pinned version, a
// rotated remote certificate, or an added/removed artifact all surface here.
func Compare(locked, current Lockfile) Diff {
	lockedByID := locked.byID()
	currentByID := current.byID()

	var changes []Change

	for _, cur := range current.Artifacts {
		prev, ok := lockedByID[cur.ID]
		if !ok {
			changes = append(changes, Change{Kind: DriftAdded, ID: cur.ID, Name: cur.Name})
			continue
		}
		if cur.ContentHash != prev.ContentHash {
			changes = append(changes, Change{
				Kind: DriftContentChanged, ID: cur.ID, Name: cur.Name,
				Old: prev.ContentHash, New: cur.ContentHash,
			})
		}
		if cur.Source.Ref != prev.Source.Ref {
			changes = append(changes, Change{
				Kind: DriftVersionChanged, ID: cur.ID, Name: cur.Name,
				Old: prev.Source.Ref, New: cur.Source.Ref,
			})
		}
		if cur.Source.Integrity != prev.Source.Integrity {
			changes = append(changes, Change{
				Kind: DriftIntegrityChanged, ID: cur.ID, Name: cur.Name,
				Old: prev.Source.Integrity, New: cur.Source.Integrity,
			})
		}
		if cur.Source.CertSPKI != prev.Source.CertSPKI {
			changes = append(changes, Change{
				Kind: DriftCertRotated, ID: cur.ID, Name: cur.Name,
				Old: prev.Source.CertSPKI, New: cur.Source.CertSPKI,
			})
		}
	}

	for _, prev := range locked.Artifacts {
		if _, ok := currentByID[prev.ID]; !ok {
			changes = append(changes, Change{Kind: DriftRemoved, ID: prev.ID, Name: prev.Name})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].ID != changes[j].ID {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].Kind < changes[j].Kind
	})
	return Diff{Changes: changes}
}

// NewFindings returns findings present in current but not in locked, at or
// above the given severity. verify --ci uses this to fail a build on newly
// introduced critical/high issues without re-flagging accepted ones.
func NewFindings(locked, current Lockfile, min finding.Severity) []finding.Finding {
	lockedByID := locked.byID()
	var out []finding.Finding
	for _, cur := range current.Artifacts {
		prev, ok := lockedByID[cur.ID]
		seen := map[string]bool{}
		if ok {
			for _, f := range prev.Findings {
				seen[findingKey(f)] = true
			}
		}
		for _, f := range cur.Findings {
			if f.Severity.AtLeast(min) && !seen[findingKey(f)] {
				out = append(out, f)
			}
		}
	}
	return out
}

func findingKey(f finding.Finding) string {
	return f.RuleID + "|" + f.File + "|" + strconv.Itoa(f.Line)
}
