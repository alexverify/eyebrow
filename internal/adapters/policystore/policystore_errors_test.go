package policystore

import (
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// Load surfaces read errors other than "not exist". A directory in place of a
// file reads as an error, not as a missing-file default.
func TestLoadReadErrorIsNotSwallowed(t *testing.T) {
	dir := t.TempDir() // a directory, not a regular file
	_, present, err := Load(dir)
	if err == nil {
		t.Fatal("expected a read error for a directory path")
	}
	if present {
		t.Error("present should be false on a read error")
	}
}

// Save fails cleanly when the target directory does not exist (CreateTemp
// cannot place its temp file), rather than partially writing.
func TestSaveFailsWhenDirMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir", "eyebrow.policy.json")
	if err := Save(missing, policy.Default()); err == nil {
		t.Error("expected an error saving into a missing directory")
	}
}
