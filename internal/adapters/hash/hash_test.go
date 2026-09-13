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

// eyebrow's own state files must not count toward an artifact's digest. A
// root-level skill hashes the repo root, and scan writes the lockfile into
// that same root, so including it would change the digest on every
// regeneration. Same doctrine as .git: verifier metadata, not shipped code.
func TestHashSkipsEyebrowStateFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	clean, _, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "eyebrow.discover.json"), `{"version":1}`)
	writeFile(t, filepath.Join(dir, "eyebrowlock.json"), `{"artifacts":[]}`)
	writeFile(t, filepath.Join(dir, "eyebrow.policy.json"), `{}`)
	writeFile(t, filepath.Join(dir, "eyebrow.trustedkeys"), "key")
	writeFile(t, filepath.Join(dir, ".eyebrow", "snapshots", "sha256-x", "files.json"), `[]`)
	got, files, _, err := New().Hash(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if clean != got {
		t.Error("eyebrow state files leaked into the digest")
	}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "eyebrow") || strings.HasPrefix(f.Path, ".eyebrow") {
			t.Errorf("eyebrow state file listed: %q", f.Path)
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

// A skill directory may itself be a symlink (OpenClaude follows them when it
// loads skills). WalkDir does not follow a symlinked root, so without
// resolving it the walk yields no files and the artifact gets the empty
// digest: it appears in the lockfile while its contents go unhashed, and an
// edit behind the link passes verify. The hasher must resolve the root.
func TestHashFollowsSymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	writeFile(t, filepath.Join(target, "SKILL.md"), "body")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}

	want, wantFiles, _, err := New().Hash(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	got, files, _, err := New().Hash(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(wantFiles) || len(files) != 1 || files[0].Path != "SKILL.md" {
		t.Fatalf("files via symlink = %+v, want %+v", files, wantFiles)
	}
	if got != want {
		t.Errorf("digest via symlink = %s, want %s", got, want)
	}
}
