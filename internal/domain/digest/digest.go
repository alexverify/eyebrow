// Package digest implements agentguard's canonical, content-addressable
// integrity primitive. It is pure (no filesystem or network access): callers
// supply file paths and pre-computed per-file hashes, and the package folds
// them into a single deterministic Merkle-style root.
//
// Keeping this logic IO-free is deliberate. The whole product's trust model
// rests on "the same bytes always produce the same digest, regardless of OS,
// walk order, or machine", so it must be exhaustively unit-testable without
// touching disk.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Prefix labels a hash with its algorithm, matching the lockfile encoding
// (e.g. "sha256-ab12…"). Storing the algorithm alongside the value keeps the
// format forward-compatible if the hash function is ever upgraded.
const Prefix = "sha256-"

// FileHash pairs a POSIX-relative path with the hex SHA-256 of that file's
// bytes (no Prefix). The hash adapter produces these by walking a directory;
// the domain only needs the resulting pairs.
type FileHash struct {
	Path string // POSIX-relative path within the artifact root
	Hash string // lowercase hex SHA-256 of the file contents
}

// Sum returns the lowercase hex SHA-256 of b, without a prefix.
func Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Leaf computes the FileHash for a single file's contents.
func Leaf(path string, content []byte) FileHash {
	return FileHash{Path: path, Hash: Sum(content)}
}

// Root folds a set of per-file hashes into the canonical artifact digest:
//
//	root = sha256( for each file sorted by path:
//	                 path || 0x00 || sha256(file_bytes) || 0x00 )
//
// The input slice is not mutated. Files are sorted by POSIX path so the result
// is independent of discovery order. A malformed (non-hex) file hash is treated
// as opaque bytes so the function never panics; in practice Leaf always yields
// valid hex. The returned value carries the Prefix.
func Root(files []FileHash) string {
	sorted := make([]FileHash, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	h := sha256.New()
	const sep = 0x00
	for _, f := range sorted {
		h.Write([]byte(f.Path))
		h.Write([]byte{sep})
		if raw, err := hex.DecodeString(f.Hash); err == nil {
			h.Write(raw)
		} else {
			h.Write([]byte(f.Hash))
		}
		h.Write([]byte{sep})
	}
	return Prefix + hex.EncodeToString(h.Sum(nil))
}

// Inline computes the digest of a single opaque blob (used for inline sources
// such as hooks, rules, and context text). It is equivalent to a one-file tree
// keyed by a fixed path, ensuring inline and file-backed artifacts share one
// hashing scheme.
func Inline(content []byte) string {
	return Root([]FileHash{Leaf("<inline>", content)})
}
