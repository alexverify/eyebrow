//go:build unix

package discover

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// A FIFO named SKILL.md is never opened: opening it would block check.
func TestDirDoesNotOpenFIFOSkillMd(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "SKILL.md"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan artifact.Artifact, 1)
	go func() { done <- dirArtifact(t, root) }()
	select {
	case a := <-done:
		if a.Type != artifact.TypeSkill || !unsafeEntryOn(a, "SKILL.md") {
			t.Fatalf("want skill with CHECK-UNSAFE-ENTRY on SKILL.md, got %+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Discover hung on a FIFO SKILL.md")
	}
}
