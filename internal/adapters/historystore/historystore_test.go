package historystore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/posture"
)

func TestAppendAndReadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "history.jsonl") // parent dir created on demand
	a := posture.Posture{Total: 5, Trusted: 5, At: time.Unix(1000, 0).UTC()}
	b := posture.Posture{Total: 6, Trusted: 5, Review: 1, At: time.Unix(2000, 0).UTC()}
	if err := Append(path, a); err != nil {
		t.Fatalf("Append a: %v", err)
	}
	if err := Append(path, b); err != nil {
		t.Fatalf("Append b: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got[0].Total != 5 || got[1].Review != 1 {
		t.Fatalf("history not in append order: %+v", got)
	}
}

func TestReadMissingIsEmpty(t *testing.T) {
	got, err := Read(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || got != nil {
		t.Fatalf("missing history → (nil,nil), got (%+v,%v)", got, err)
	}
}

func TestReadSkipsBadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	if err := os.WriteFile(path, []byte(`{"total":3}`+"\n"+`{bad`+"\n"+`{"total":4}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got[0].Total != 3 || got[1].Total != 4 {
		t.Fatalf("bad line should be skipped: %+v", got)
	}
}
