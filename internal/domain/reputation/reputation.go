// Package reputation models an opt-in, privacy-preserving community trust signal
// (theme H3): "this exact artifact hash is trusted by N other eyebrow users, first
// seen 2026-04." It is the one signal a purely local tool cannot build alone — a
// network effect that sharpens as adoption grows.
//
// Privacy is structural, not promised. The corpus is keyed solely by content
// hash: no code, no identity, no source. A query is a local map lookup against a
// corpus the user already holds, so nothing leaves the machine. Like the
// advisory feed it is pure and degrades to a silent no-op when absent — a miss
// is "unknown," never a negative claim about the artifact.
package reputation

import (
	"strings"
	"time"
)

// Signal is the community trust standing of one content hash.
type Signal struct {
	Hash      string    `json:"hash"`
	Trusters  int       `json:"trusters"`  // distinct users who trust this exact hash
	FirstSeen time.Time `json:"firstSeen"` // when the hash first entered the corpus
}

// Source is a content-hash → Signal corpus: a snapshot of the reputation set the
// user opted into. An empty or nil Source is a valid silent no-op.
type Source map[string]Signal

// Lookup returns the signal for a content hash, or false when the corpus has no
// entry for it. An empty hash never resolves.
func (s Source) Lookup(contentHash string) (Signal, bool) {
	if s == nil || contentHash == "" {
		return Signal{}, false
	}
	sig, ok := s[strings.ToLower(contentHash)]
	return sig, ok
}

// Grade is the qualitative trust tier derived from how many users vouch for a
// hash. It keeps the count from being over-read: two trusters is not fifty.
type Grade string

const (
	GradeUnknown     Grade = "unknown"     // not in the corpus
	GradeEmerging    Grade = "emerging"    // a handful of trusters
	GradeEstablished Grade = "established" // widely vouched for
)

// establishedFloor is the truster count at which a hash is "widely trusted."
const establishedFloor = 10

// Grade buckets the truster count into a tier.
func (sig Signal) Grade() Grade {
	switch {
	case sig.Trusters <= 0:
		return GradeUnknown
	case sig.Trusters < establishedFloor:
		return GradeEmerging
	default:
		return GradeEstablished
	}
}
