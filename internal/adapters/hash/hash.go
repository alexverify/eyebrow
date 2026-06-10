// Package hash adapts the pure domain digest algorithm to the filesystem. It
// walks an artifact directory, hashes each regular file, and folds the results
// into the canonical content digest. All cryptographic logic lives in
// internal/domain/digest; this package only handles IO and traversal.
package hash

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/digest"
)

// Hasher computes content digests over directories or single files.
type Hasher struct {
	// skipDirs are directory names excluded from traversal. .git is metadata,
	// not shipped code. node_modules is deliberately NOT skipped: it is the
	// code that actually runs and must be part of the integrity anchor.
	skipDirs map[string]bool
}

// New returns a Hasher with default exclusions.
func New() *Hasher {
	return &Hasher{skipDirs: map[string]bool{".git": true}}
}

// Hash walks root and returns the canonical content digest plus per-file
// hashes (sorted by POSIX path). root may be a directory or a single file.
func (h *Hasher) Hash(ctx context.Context, root string) (string, []artifact.FileRef, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", nil, err
	}

	var (
		leaves []digest.FileHash
		files  []artifact.FileRef
	)

	add := func(rel string, b []byte) {
		leaf := digest.Leaf(rel, b)
		leaves = append(leaves, leaf)
		files = append(files, artifact.FileRef{Path: rel, Hash: leaf.Hash})
	}

	if !info.IsDir() {
		b, err := os.ReadFile(root)
		if err != nil {
			return "", nil, err
		}
		add(filepath.Base(root), b)
		return digest.Root(leaves), files, nil
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if h.skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// Hash only regular files; skip symlinks, sockets, devices.
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		add(filepath.ToSlash(rel), b)
		return nil
	})
	if walkErr != nil {
		return "", nil, walkErr
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return digest.Root(leaves), files, nil
}
