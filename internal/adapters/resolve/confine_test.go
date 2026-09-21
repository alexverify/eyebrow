package resolve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// confineFixture returns a scan root and a file outside it.
func confineFixture(t *testing.T) (root, outside string) {
	t.Helper()
	// Local.Root must be absolute and symlink-resolved (the engine resolves
	// it once per request); on macOS t.TempDir sits under the /var symlink.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "skills", "foo"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside = filepath.Join(base, "host-secret")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

func assertRefused(t *testing.T, res resolutionView, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("refusal must be a finding, not an error: %v", err)
	}
	if res.LocalPath != "" || res.ContentHash != "" {
		t.Fatalf("refused source must not be readable: LocalPath=%q ContentHash=%q", res.LocalPath, res.ContentHash)
	}
	for _, w := range res.Warnings {
		if w.RuleID == finding.RuleLocalOutsideRoot {
			if w.Severity != finding.SeverityHigh {
				t.Fatalf("severity %q, want high", w.Severity)
			}
			return
		}
	}
	t.Fatalf("no %s finding: %+v", finding.RuleLocalOutsideRoot, res.Warnings)
}

type resolutionView struct {
	LocalPath, ContentHash string
	Warnings               []finding.Finding
}

func resolveLocal(t *testing.T, l Local, ref string) (resolutionView, error) {
	t.Helper()
	res, err := l.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceLocal, Ref: ref})
	return resolutionView{res.LocalPath, res.ContentHash, res.Warnings}, err
}

func TestLocalConfinedRefusesAbsolutePathOutsideRoot(t *testing.T) {
	root, outside := confineFixture(t)
	res, err := resolveLocal(t, Local{Root: root}, outside)
	assertRefused(t, res, err)
}

func TestLocalUnconfinedAcceptsAbsolutePathOutsideRoot(t *testing.T) {
	_, outside := confineFixture(t)
	res, err := resolveLocal(t, Local{}, outside)
	if err != nil || res.LocalPath == "" {
		t.Fatalf("unconfined local source must resolve: %+v %v", res, err)
	}
}

func TestLocalConfinedRefusesDirectoryOutsideRoot(t *testing.T) {
	root, outside := confineFixture(t)
	res, err := resolveLocal(t, Local{Root: root}, filepath.Dir(outside))
	assertRefused(t, res, err)
}

func TestLocalConfinedAcceptsRelativePathInsideRoot(t *testing.T) {
	root, _ := confineFixture(t)
	t.Chdir(root)
	res, err := resolveLocal(t, Local{Root: root}, filepath.Join("skills", "foo"))
	if err != nil || res.LocalPath == "" {
		t.Fatalf("relative path inside the root must resolve: %+v %v", res, err)
	}
}

func TestLocalConfinedAcceptsTheRootItself(t *testing.T) {
	root, _ := confineFixture(t)
	res, err := resolveLocal(t, Local{Root: root}, root)
	if err != nil || res.LocalPath == "" {
		t.Fatalf("the root itself must resolve: %+v %v", res, err)
	}
}

func TestLocalConfinedRefusesSymlinkLeavingRoot(t *testing.T) {
	root, outside := confineFixture(t)
	link := filepath.Join(root, "server")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := resolveLocal(t, Local{Root: root}, link)
	assertRefused(t, res, err)
}

func TestLocalConfinedRefusesMissingPath(t *testing.T) {
	root, _ := confineFixture(t)
	res, err := resolveLocal(t, Local{Root: root}, filepath.Join(root, "missing"))
	assertRefused(t, res, err)
}

func TestLocalConfinedRefusesSiblingWithRootPrefix(t *testing.T) {
	root, _ := confineFixture(t)
	sibling := root + "-other"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := resolveLocal(t, Local{Root: root}, sibling)
	assertRefused(t, res, err)
}

func TestOfflineRouterConfines(t *testing.T) {
	root, outside := confineFixture(t)
	r := NewOfflineRouterWith(RouterOptions{ConfineRoot: root})
	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceLocal, Ref: outside})
	assertRefused(t, resolutionView{res.LocalPath, res.ContentHash, res.Warnings}, err)
}

func TestRouterConfines(t *testing.T) {
	root, outside := confineFixture(t)
	r := NewRouterWith(RouterOptions{ConfineRoot: root})
	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceLocal, Ref: outside})
	assertRefused(t, resolutionView{res.LocalPath, res.ContentHash, res.Warnings}, err)
}

func TestLocalConfinedRefusesARelativeRoot(t *testing.T) {
	root, _ := confineFixture(t)
	t.Chdir(root)
	res, err := resolveLocal(t, Local{Root: "."}, filepath.Join("skills", "foo"))
	assertRefused(t, res, err)
}

func TestLocalConfinedOpensTheCheckedPath(t *testing.T) {
	root, _ := confineFixture(t)
	target := filepath.Join(root, "skills", "foo")
	link := filepath.Join(root, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := resolveLocal(t, Local{Root: root}, link)
	if err != nil {
		t.Fatal(err)
	}
	if res.LocalPath != target {
		t.Fatalf("LocalPath = %q, want the checked real path %q", res.LocalPath, target)
	}
}

func TestLocalOutsideRootExplanationCoversMissingSources(t *testing.T) {
	root, _ := confineFixture(t)
	t.Chdir(root)
	res, err := resolveLocal(t, Local{Root: root}, "node")
	assertRefused(t, res, err)
	want := "local source is outside the scanned tree or missing from it, and was not read"
	if got := res.Warnings[len(res.Warnings)-1].Explanation; got != want {
		t.Fatalf("explanation %q, want %q", got, want)
	}
}
