package snapshotstore

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	files := map[string][]byte{
		"main.go":       []byte("package main\nfunc main() {}\n"),
		"sub/helper.py": []byte("print('hi')\n"),
		"logo.bin":      {0x00, 0x01, 0x02, 0xff}, // binary survives via base64
	}
	if err := s.Put("sha256-abc123", files); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("sha256-abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(files) {
		t.Fatalf("got %d files, want %d", len(got), len(files))
	}
	for path, want := range files {
		if !bytes.Equal(got[path], want) {
			t.Errorf("%s round-trip mismatch: got %q", path, got[path])
		}
	}
}

func TestGetMissingIsNilNoError(t *testing.T) {
	s := New(t.TempDir())
	got, err := s.Get("sha256-never-stored")
	if err != nil {
		t.Fatalf("a missing blob must not error: %v", err)
	}
	if got != nil {
		t.Errorf("a missing blob should be nil, got %v", got)
	}
	if s.Has("sha256-never-stored") {
		t.Errorf("Has should be false for an unstored hash")
	}
}

func TestGetMissingStoreDir(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "does-not-exist"))
	if got, err := s.Get("h"); err != nil || got != nil {
		t.Errorf("absent store should degrade to nil,nil; got %v, %v", got, err)
	}
}

func TestHasAfterPut(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Put("h1", map[string][]byte{"f": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if !s.Has("h1") {
		t.Errorf("Has should be true after Put")
	}
}

func TestPruneRemovesUnreferenced(t *testing.T) {
	s := New(t.TempDir())
	for _, h := range []string{"keep1", "keep2", "drop1", "drop2"} {
		if err := s.Put(h, map[string][]byte{"f": []byte(h)}); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.Prune(map[string]bool{"keep1": true, "keep2": true})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("Prune removed %d, want 2", removed)
	}
	if !s.Has("keep1") || !s.Has("keep2") {
		t.Errorf("kept blobs must survive prune")
	}
	if s.Has("drop1") || s.Has("drop2") {
		t.Errorf("unreferenced blobs must be removed")
	}
}

func TestEmptyHashIsNoOp(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Put("", map[string][]byte{"f": []byte("x")}); err != nil {
		t.Errorf("Put with empty hash should be a silent no-op, got %v", err)
	}
	if s.Has("") {
		t.Errorf("empty hash is not addressable")
	}
}
