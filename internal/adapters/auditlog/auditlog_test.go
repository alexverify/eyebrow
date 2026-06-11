package auditlog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/domain/audit"
)

func TestEmitAppendsOneLinePerEvent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	sink := New(dir)
	ctx := context.Background()

	at := time.Date(2026, 6, 11, 22, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{At: at, Session: "s1", Server: "github", Kind: audit.KindSessionStart},
		{At: at.Add(time.Second), Session: "s1", Server: "github", Kind: audit.KindToolCall,
			Tool: "create_issue", ArgsDigest: "sha256-abc", DurationMs: 120, Status: audit.StatusOK},
	}
	for _, e := range events {
		if err := sink.Emit(ctx, e); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}

	b, err := os.ReadFile(filepath.Join(dir, "2026-06-11.jsonl"))
	if err != nil {
		t.Fatalf("audit file not written: %v", err)
	}
	lines := splitLines(b)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), b)
	}
	var got audit.Event
	if err := json.Unmarshal(lines[1], &got); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v", err)
	}
	if got.Tool != "create_issue" || got.Status != audit.StatusOK || got.DurationMs != 120 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestEmitSplitsFilesByDay(t *testing.T) {
	dir := t.TempDir()
	sink := New(dir)
	ctx := context.Background()

	day1 := time.Date(2026, 6, 11, 23, 59, 0, 0, time.UTC)
	day2 := time.Date(2026, 6, 12, 0, 1, 0, 0, time.UTC)
	_ = sink.Emit(ctx, audit.Event{At: day1, Kind: audit.KindSessionStart})
	_ = sink.Emit(ctx, audit.Event{At: day2, Kind: audit.KindServerExit})

	for _, name := range []string{"2026-06-11.jsonl", "2026-06-12.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestFilePermissionsArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	sink := New(dir)
	at := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	if err := sink.Emit(context.Background(), audit.Event{At: at, Kind: audit.KindSessionStart}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "2026-06-11.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit file perm = %o, want 600 (may hold sensitive metadata)", perm)
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
