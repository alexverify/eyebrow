package resolve

import (
	"reflect"
	"testing"

	"github.com/alexverify/assay/internal/domain/artifact"
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
