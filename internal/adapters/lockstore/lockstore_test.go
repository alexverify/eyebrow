package lockstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

func nowFixture() time.Time {
	return time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
}

func sampleLockfile() lockfile.Lockfile {
	return lockfile.Build(
		[]artifact.Artifact{
			{ID: "b", Tool: "cursor", Type: artifact.TypeSkill, Name: "two"},
			{ID: "a", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "one"},
		},
		// fixed time so the round-trip comparison is deterministic
		nowFixture(),
		"eyebrow-test",
	)
}

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eyebrowlock.json")
	store := New()
	want := sampleLockfile()

	if err := store.Write(context.Background(), path, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Read(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.Generator != want.Generator {
		t.Errorf("metadata mismatch: got %+v", got)
	}
	if len(got.Artifacts) != len(want.Artifacts) {
		t.Fatalf("artifact count = %d, want %d", len(got.Artifacts), len(want.Artifacts))
	}
	// Build sorts by ID, so "a" must come first after a round trip.
	if got.Artifacts[0].ID != "a" || got.Artifacts[1].ID != "b" {
		t.Errorf("artifact order not preserved: %q, %q", got.Artifacts[0].ID, got.Artifacts[1].ID)
	}
}

func TestWriteIsIndentedWithTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eyebrowlock.json")
	if err := New().Write(context.Background(), path, sampleLockfile()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("lockfile does not end with a trailing newline")
	}
	if !containsIndent(b) {
		t.Error("lockfile is not indented")
	}
}

func TestReadMissingReturnsErrNoLockfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	_, err := New().Read(context.Background(), path)
	if !errors.Is(err, ports.ErrNoLockfile) {
		t.Errorf("err = %v, want ErrNoLockfile", err)
	}
}

func TestReadInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Read(context.Background(), path); err == nil {
		t.Error("expected parse error for invalid JSON")
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eyebrowlock.json")
	store := New()
	if store.Exists(path) {
		t.Error("Exists reported true before write")
	}
	if err := store.Write(context.Background(), path, sampleLockfile()); err != nil {
		t.Fatal(err)
	}
	if !store.Exists(path) {
		t.Error("Exists reported false after write")
	}
}

func containsIndent(b []byte) bool {
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '\n' && b[i+1] == ' ' && b[i+2] == ' ' {
			return true
		}
	}
	return false
}
