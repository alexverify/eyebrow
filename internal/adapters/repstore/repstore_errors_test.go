package repstore

import (
	"os"
	"path/filepath"
	"testing"
)

// A read error other than "not exist" (here: the path is a directory) must
// surface, not silently degrade to an empty corpus.
func TestLoadReadErrorSurfaces(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Error("expected a read error for a directory path")
	}
}

// Malformed JSON is a real error, not a silent empty corpus.
func TestLoadMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected a parse error for malformed JSON")
	}
}

// A literal JSON null unmarshals to a nil map; Load normalizes it to a
// non-nil empty corpus so callers can do lookups without a nil check.
func TestLoadNullYieldsEmptyCorpus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, []byte("null"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if src == nil {
		t.Error("Load(null) returned a nil corpus, want non-nil empty")
	}
	if len(src) != 0 {
		t.Errorf("corpus length = %d, want 0", len(src))
	}
}
