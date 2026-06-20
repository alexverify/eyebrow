// Package lockfile defines the eyebrowlock.json model and the drift-detection
// logic that powers `eyebrow verify` — the rug-pull detector.
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

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// CanonicalBytes returns the deterministic serialization of the lockfile used
// for signing: the same content with the signature field cleared, so a
// signature commits to everything except itself. Entries are already sorted by
// Build, and JSON marshals map keys in order, so the output is stable.
func CanonicalBytes(lf Lockfile) ([]byte, error) {
	lf.Sig = ""
	return json.Marshal(lf)
}

// ApprovalSigningBytes returns the canonical bytes an approval signature
// commits to: the artifact's stable ID and its content hash, newline-joined.
// Binding the content hash means any later content change (a rug pull)
// invalidates the approval; binding the ID stops an approval being moved to a
// different artifact.
func ApprovalSigningBytes(e Entry) []byte {
	return []byte(e.ID + "\n" + e.ContentHash)
}

// Version is the current eyebrowlock.json schema version.
const Version = 1

// Approval records a human (optionally signed) sign-off on an artifact's
// current content. verify --ci can require approval before allowing a build.
type Approval struct {
	Status string    `json:"status"` // "approved" | "pending" | "rejected"
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitempty"`
	Sig    string    `json:"sig,omitempty"` // ed25519:… over the artifact ContentHash
}

// Entry is one artifact as recorded in the lockfile, with its approval and
// remediation state. The artifact fields are flattened into the JSON object.
type Entry struct {
	artifact.Artifact
	Approval *Approval `json:"approval,omitempty"`
	// Quarantined disables an artifact pending review: the policy gate always
	// fails a quarantined artifact, so it cannot ship.
	Quarantined bool `json:"quarantined,omitempty"`
	// Frozen pins an artifact: any drift on it (update, mutation, or broken
	// integrity) is a hard policy violation, not a reviewable change.
	Frozen bool `json:"frozen,omitempty"`
	// SafeFindings records per-finding "accepted false positive" sign-offs: a
	// finding flagged safe stays visible but no longer fails the policy gate.
	SafeFindings []FindingAck `json:"safeFindings,omitempty"`
}

// FindingAck marks one finding as an accepted false positive ("flagged safe").
// Key is the stable finding key (see FindingKey); Hash records the artifact's
// content hash at flag time so the UI can note when the code changed afterwards.
type FindingAck struct {
	Key  string    `json:"key"`
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at,omitempty"`
	Hash string    `json:"hash,omitempty"`
}

// IsFindingSafe reports whether the given finding key has been flagged safe on
// this entry.
func (e Entry) IsFindingSafe(key string) bool {
	for _, s := range e.SafeFindings {
		if s.Key == key {
			return true
		}
	}
	return false
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

// DriftClass is the per-artifact, display-level interpretation of a change
// between the locked and current snapshots. Where Compare reports every changed
// field, Classify answers the question the dashboard actually asks: does this
// change look like a developer-initiated update, or an unexplained mutation
// (the rug-pull signal)?
type DriftClass string

const (
	DriftClassNone    DriftClass = "none"    // nothing changed
	DriftClassUpdated DriftClass = "updated" // content + pinned ref moved together, integrity intact → expected
	DriftClassMutated DriftClass = "mutated" // content moved while the pinned ref held → unexplained (rug pull)
	DriftClassBroken  DriftClass = "broken"  // an update whose integrity could not be verified → unverifiable
	DriftClassAdded   DriftClass = "added"   // present now, absent in the lockfile
	DriftClassRemoved DriftClass = "removed" // present in the lockfile, absent now
)

// Classify maps each artifact ID to its DriftClass. Unchanged artifacts map to
// DriftClassNone, so callers may treat a missing key and an explicit None
// identically.
func Classify(locked, current Lockfile) map[string]DriftClass {
	lockedByID := locked.byID()
	currentByID := current.byID()
	out := make(map[string]DriftClass, len(current.Artifacts))

	for _, cur := range current.Artifacts {
		prev, ok := lockedByID[cur.ID]
		if !ok {
			out[cur.ID] = DriftClassAdded
			continue
		}
		out[cur.ID] = classifyPair(prev, cur)
	}
	for _, prev := range locked.Artifacts {
		if _, ok := currentByID[prev.ID]; !ok {
			out[prev.ID] = DriftClassRemoved
		}
	}
	return out
}

// classifyPair classifies one matched (locked, current) pair.
func classifyPair(prev, cur Entry) DriftClass {
	contentChanged := cur.ContentHash != prev.ContentHash
	refChanged := cur.Source.Ref != prev.Source.Ref
	integrityChanged := cur.Source.Integrity != prev.Source.Integrity
	certChanged := cur.Source.CertSPKI != prev.Source.CertSPKI

	switch {
	case !contentChanged && !refChanged && !integrityChanged && !certChanged:
		return DriftClassNone
	case contentChanged && refChanged:
		// A real release moves both the pinned ref and the bytes. It is
		// verifiable when we could re-pin it.
		if updateVerifiable(cur.Source) {
			return DriftClassUpdated
		}
		return DriftClassBroken
	case contentChanged && !refChanged:
		// Same pinned version, different bytes: postmark-mcp / MCPoison. Loudest.
		return DriftClassMutated
	case !contentChanged && integrityChanged:
		// Integrity moved under a stable content hash — internally inconsistent.
		return DriftClassBroken
	default:
		// Metadata-only movement (ref retag, cert rotation) with stable content.
		return DriftClassUpdated
	}
}

// updateVerifiable reports whether a moved source can be re-pinned to a fresh
// integrity anchor. npm packages must carry a new integrity; git/url/local/
// inline have no integrity, so a matching content+ref move is taken at face value.
func updateVerifiable(s artifact.Source) bool {
	if s.Kind == artifact.SourceNPM {
		return s.Integrity != ""
	}
	return true
}

// CapabilityDiff is the set difference between an artifact's locked and current
// declared capabilities. Capability expansion after an update — "it can now read
// your filesystem and make outbound calls" — is a primary, low-noise trust signal.
type CapabilityDiff struct {
	ExecAdded         bool     `json:"execAdded,omitempty"`
	ExecRemoved       bool     `json:"execRemoved,omitempty"`
	NetworkAdded      []string `json:"networkAdded,omitempty"`
	NetworkRemoved    []string `json:"networkRemoved,omitempty"`
	FilesystemAdded   []string `json:"filesystemAdded,omitempty"`
	FilesystemRemoved []string `json:"filesystemRemoved,omitempty"`
}

// Expanded reports whether the artifact gained any capability — the case worth
// surfacing loudly.
func (d CapabilityDiff) Expanded() bool {
	return d.ExecAdded || len(d.NetworkAdded) > 0 || len(d.FilesystemAdded) > 0
}

// DiffCapabilities returns the capabilities present in cur but not prev, and
// vice versa. Output slices are sorted for deterministic display.
func DiffCapabilities(prev, cur artifact.Capabilities) CapabilityDiff {
	return CapabilityDiff{
		ExecAdded:         cur.Exec && !prev.Exec,
		ExecRemoved:       prev.Exec && !cur.Exec,
		NetworkAdded:      stringsMinus(cur.Network, prev.Network),
		NetworkRemoved:    stringsMinus(prev.Network, cur.Network),
		FilesystemAdded:   stringsMinus(cur.Filesystem, prev.Filesystem),
		FilesystemRemoved: stringsMinus(prev.Filesystem, cur.Filesystem),
	}
}

// stringsMinus returns the sorted elements of a that are not in b.
func stringsMinus(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if !set[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// FileDiff is the per-file change between an artifact's locked and current
// manifests, by path. It answers "which files changed in this drift" without
// storing any content: the lockfile records per-file hashes, so a moved hash on
// a stable path is a Modified file, a new path is Added, a vanished path Removed.
// This is the offline, content-free core of the rug-pull diff view (H1).
type FileDiff struct {
	Added    []string `json:"added,omitempty"`    // paths present now, absent before
	Removed  []string `json:"removed,omitempty"`  // paths present before, absent now
	Modified []string `json:"modified,omitempty"` // same path, different hash
}

// Changed reports whether any file was added, removed, or modified.
func (d FileDiff) Changed() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Modified) > 0
}

// DiffFiles compares two file manifests by path and returns the added, removed,
// and modified paths. Output slices are sorted for deterministic display.
func DiffFiles(prev, cur []artifact.FileRef) FileDiff {
	prevByPath := make(map[string]string, len(prev))
	for _, f := range prev {
		prevByPath[f.Path] = f.Hash
	}
	curByPath := make(map[string]string, len(cur))
	for _, f := range cur {
		curByPath[f.Path] = f.Hash
	}

	var d FileDiff
	for _, f := range cur {
		old, ok := prevByPath[f.Path]
		switch {
		case !ok:
			d.Added = append(d.Added, f.Path)
		case old != f.Hash:
			d.Modified = append(d.Modified, f.Path)
		}
	}
	for _, f := range prev {
		if _, ok := curByPath[f.Path]; !ok {
			d.Removed = append(d.Removed, f.Path)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	return d
}

// ArtifactFinding tags a finding with the ID of the artifact that carries it, so
// callers can resolve per-artifact state (e.g. a "flagged safe" acknowledgement).
type ArtifactFinding struct {
	ArtifactID string
	finding.Finding
}

// NewFindings returns findings present in current but not in locked, at or
// above the given severity. verify --ci uses this to fail a build on newly
// introduced critical/high issues without re-flagging accepted ones.
func NewFindings(locked, current Lockfile, min finding.Severity) []finding.Finding {
	af := NewFindingsByArtifact(locked, current, min)
	out := make([]finding.Finding, len(af))
	for i, x := range af {
		out[i] = x.Finding
	}
	return out
}

// NewFindingsByArtifact is NewFindings with each finding tagged by its artifact
// ID, letting the gate look up per-finding "flagged safe" acknowledgements.
func NewFindingsByArtifact(locked, current Lockfile, min finding.Severity) []ArtifactFinding {
	lockedByID := locked.byID()
	var out []ArtifactFinding
	for _, cur := range current.Artifacts {
		prev, ok := lockedByID[cur.ID]
		seen := map[string]bool{}
		if ok {
			for _, f := range prev.Findings {
				seen[FindingKey(f)] = true
			}
		}
		for _, f := range cur.Findings {
			if f.Severity.AtLeast(min) && !seen[FindingKey(f)] {
				out = append(out, ArtifactFinding{ArtifactID: cur.ID, Finding: f})
			}
		}
	}
	return out
}

// FindingKey is the stable identity of a finding within an artifact: its rule,
// file, and line. Used to match a finding against a "flagged safe" sign-off.
func FindingKey(f finding.Finding) string {
	return f.RuleID + "|" + f.File + "|" + strconv.Itoa(f.Line)
}
