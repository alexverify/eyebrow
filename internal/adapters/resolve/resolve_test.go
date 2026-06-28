package resolve

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
)

func TestNewRouterWiresRealResolvers(t *testing.T) {
	r := NewRouter()
	want := map[artifact.SourceKind]any{
		artifact.SourceNPM:       NPM{},
		artifact.SourceGit:       Git{},
		artifact.SourceURL:       URL{},
		artifact.SourceLocal:     Local{},
		artifact.SourceInline:    Inline{},
		artifact.SourceContainer: Container{},
	}
	for kind, wantVal := range want {
		got, ok := r.resolvers[kind]
		if !ok {
			t.Errorf("no resolver registered for %q", kind)
			continue
		}
		if gotType, wantType := reflect.TypeOf(got), reflect.TypeOf(wantVal); gotType != wantType {
			t.Errorf("kind %q wired to %s, want %s", kind, gotType, wantType)
		}
	}
}

func TestRouterUnsupportedKind(t *testing.T) {
	r := NewRouter()
	_, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceKind("nope")})
	if !errors.Is(err, ports.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestRouterDispatchesInline(t *testing.T) {
	r := NewRouter()
	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceInline, Ref: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentHash != digest.Inline([]byte("hi")) {
		t.Errorf("router did not delegate to Inline resolver: %q", res.ContentHash)
	}
}

func TestLocalResolve(t *testing.T) {
	dir := t.TempDir()
	res, err := Local{}.Resolve(context.Background(), artifact.Source{Ref: dir})
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	if res.LocalPath != abs || res.PinnedRef != abs {
		t.Errorf("LocalPath/PinnedRef = %q/%q, want %q", res.LocalPath, res.PinnedRef, abs)
	}
}

func TestLocalResolveFallsBackToCommand(t *testing.T) {
	dir := t.TempDir()
	// Ref empty → resolver should use Command as the path.
	res, err := Local{}.Resolve(context.Background(), artifact.Source{Command: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.LocalPath == "" {
		t.Error("expected Command to be used as the local path")
	}
}

func TestLocalResolveMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := (Local{}).Resolve(context.Background(), artifact.Source{Ref: missing}); err == nil {
		t.Error("expected error for missing local path")
	}
}

func TestInlineResolve(t *testing.T) {
	res, err := Inline{}.Resolve(context.Background(), artifact.Source{Ref: "literal content"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentHash != digest.Inline([]byte("literal content")) {
		t.Errorf("ContentHash = %q, want inline digest", res.ContentHash)
	}
	if res.LocalPath != "" {
		t.Errorf("inline resolution should not set LocalPath, got %q", res.LocalPath)
	}
}
