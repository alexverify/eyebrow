// Package provenance grades how verifiable an artifact's origin is, the
// agent-specific analog of a SLSA level. It is pure: it reads only the source
// pins assay already records (ref, integrity, cert) plus whether a trusted
// key signed the approval, and reports a ladder of rungs.
//
// The top rung — publisher verification — reflects an upstream build-provenance
// attestation captured at scan time (e.g. npm Sigstore provenance, recorded on
// Source.Provenance). A broken or absent rung is information, not a failure.
package provenance

import "github.com/alexverify/assay/internal/domain/artifact"

// Rung is one step on the provenance ladder.
type Rung struct {
	Label string `json:"label"`
	OK    bool   `json:"ok"`
}

// Ladder is the assessed provenance: how many consecutive rungs from the bottom
// are satisfied (Level), out of Max, plus the per-rung detail.
type Ladder struct {
	Level int    `json:"level"`
	Max   int    `json:"max"`
	Rungs []Rung `json:"rungs"`
}

// Assess builds the ladder for a source. signed reports whether a trusted key
// approved the artifact (computed by the caller from the lockfile + keyring).
func Assess(s artifact.Source, signed bool) Ladder {
	rungs := []Rung{
		{Label: "source pinned", OK: s.Ref != ""},
		{Label: "integrity anchored", OK: anchored(s)},
		{Label: "signed by a trusted key", OK: signed},
		{Label: "publisher verified", OK: s.Provenance != ""}, // upstream build-provenance attestation
	}
	level := 0
	for _, r := range rungs {
		if !r.OK {
			break
		}
		level++
	}
	return Ladder{Level: level, Max: len(rungs), Rungs: rungs}
}

// anchored reports whether the source carries a usable integrity anchor for its
// kind: npm needs an integrity hash, url a pinned cert SPKI, git a commit ref,
// and local/inline are content-addressed by definition.
func anchored(s artifact.Source) bool {
	switch s.Kind {
	case artifact.SourceNPM:
		return s.Integrity != ""
	case artifact.SourceURL:
		return s.CertSPKI != ""
	case artifact.SourceGit:
		return s.Ref != ""
	case artifact.SourceLocal, artifact.SourceInline:
		return true
	default:
		return false
	}
}
