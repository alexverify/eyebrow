//go:build unix

package cli_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/cli"
)

// A FIFO in the folder must never be opened: check reports it and returns.
func TestCheckReportsFIFOAndReturns(t *testing.T) {
	dir := stagedSkill(t, "ok\n")
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.sh"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	type result struct {
		code int
		r    checkJSON
	}
	done := make(chan result, 1)
	go func() {
		code, r, _, _ := runCheck(t, dir, "--json")
		done <- result{code, r}
	}()
	select {
	case res := <-done:
		if res.code != cli.ExitDrift || !hasCheckFinding(res.r, "CHECK-UNSAFE-ENTRY", "pipe.sh") {
			t.Fatalf("exit %d, want CHECK-UNSAFE-ENTRY on pipe.sh: %+v", res.code, res.r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("check hung on a FIFO")
	}
}
