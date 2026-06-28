package hash

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHashSingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "skill.md")
	writeFile(t, f, "hello")

	root, files, _, err := New().Hash(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if root == "" {
		t.Error("empty root digest")
	}
	if len(files) != 1 || files[0].Path != "skill.md" {
		t.Fatalf("files = %+v, want single skill.md", files)
	}
}

func TestHashDeterministic(t *testing.T) {
	build := func() string {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
		writeFile(t, filepath.Join(dir, "sub", "b.txt"), "beta")
		root, _, _, err := New().Hash(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	if build() != build() {
		t.Error("hash of identical trees differs")
	}
}

func TestHashFilesSortedByPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "z.txt"), "z")
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	writeFile(t, filepath.Join(dir, "m", "n.txt"), "n")

	_, files, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(files); i++ {
		if files[i-1].Path > files[i].Path {
			t.Errorf("files not sorted: %q before %q", files[i-1].Path, files[i].Path)
		}
	}
}

func TestHashContentChangeChangesDigest(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "before")
	before, _, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f, "after")
	after, _, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Error("digest unchanged after file content changed")
	}
}

func TestHashSkipsGitMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	clean, _, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".git", "config"), "[core]")
	withGit, files, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if clean != withGit {
		t.Error(".git contents leaked into the digest")
	}
	for _, f := range files {
		if strings.HasPrefix(f.Path, ".git") {
			t.Errorf(".git file listed: %q", f.Path)
		}
	}
}

func TestHashMissingRoot(t *testing.T) {
	if _, _, _, err := New().Hash(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for missing root")
	}
}

func TestHashContextCancelled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := New().Hash(ctx, dir); err == nil {
		t.Error("expected error from cancelled context")
	}
}
