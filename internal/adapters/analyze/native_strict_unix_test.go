//go:build unix

package analyze

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// A FIFO is never opened: opening one blocks until a writer appears.
func TestStrictNativeReportsFIFOWithoutOpeningIt(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.sh"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	type result struct {
		fs  []finding.Finding
		err error
	}
	done := make(chan result, 1)
	go func() {
		fs, err := NewStrictNative().Analyze(context.Background(), artifact.Artifact{}, root)
		done <- result{fs, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !hasFinding(r.fs, finding.RuleUnsafeEntry, "pipe.sh") {
			t.Fatalf("want CHECK-UNSAFE-ENTRY on pipe.sh, got %+v", r.fs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Analyze hung on a FIFO")
	}
}
