package auditlog

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/assay/internal/domain/audit"
)

func seed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sink := New(dir)
	ctx := context.Background()
	day1 := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{At: day1, Session: "s1", Server: "github", Kind: audit.KindSessionStart},
		{At: day1.Add(time.Second), Session: "s1", Server: "github", Kind: audit.KindToolCall, Tool: "create_issue", Status: audit.StatusOK},
		{At: day1.Add(2 * time.Second), Session: "s1", Server: "github", Kind: audit.KindToolCall, Tool: "delete_repo", Status: audit.StatusDenied, Detail: "denied by github denyTools delete_*"},
		{At: day2, Session: "s2", Server: "db", Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
		{At: day2.Add(time.Second), Session: "s2", Server: "db", Kind: audit.KindEgress, Host: "api.ok.example", Status: audit.StatusOK, Redactions: 2},
	}
	for _, e := range events {
		if err := sink.Emit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadAllSortedByTime(t *testing.T) {
	dir := seed(t)
	evs, err := Read(dir, Filter{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(evs) != 5 {
		t.Fatalf("got %d events, want 5", len(evs))
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].At.Before(evs[i-1].At) {
			t.Fatal("events must be sorted ascending by time")
		}
	}
}

func TestReadFilters(t *testing.T) {
	dir := seed(t)

	byServer, _ := Read(dir, Filter{Server: "github"})
	if len(byServer) != 3 {
		t.Errorf("server filter: got %d, want 3", len(byServer))
	}

	denied, _ := Read(dir, Filter{Status: audit.StatusDenied})
	if len(denied) != 2 {
		t.Errorf("status filter: got %d, want 2", len(denied))
	}

	since := Filter{Since: time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)}
	recent, _ := Read(dir, since)
	if len(recent) != 2 {
		t.Errorf("since filter: got %d, want 2", len(recent))
	}

	egress, _ := Read(dir, Filter{Kind: audit.KindEgress})
	if len(egress) != 2 {
		t.Errorf("kind filter: got %d, want 2", len(egress))
	}
}

func TestReadMissingDirIsEmpty(t *testing.T) {
	evs, err := Read(filepath.Join(t.TempDir(), "absent"), Filter{})
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("missing dir must yield no events, got %d", len(evs))
	}
}

func TestSummarize(t *testing.T) {
	dir := seed(t)
	evs, _ := Read(dir, Filter{})
	s := Summarize(evs)

	if s.ToolCalls != 2 || s.Denied != 2 || s.Egress != 2 || s.Redactions != 2 {
		t.Errorf("summary = %+v", s)
	}
	if s.ByServer["github"] != 3 || s.ByServer["db"] != 2 {
		t.Errorf("by-server = %v", s.ByServer)
	}
	if s.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", s.Sessions)
	}
}
