package sbom

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestComponentType(t *testing.T) {
	apps := []artifact.Type{artifact.TypeMCPServer, artifact.TypePlugin, artifact.TypeHook}
	for _, ty := range apps {
		if got := componentType(ty); got != "application" {
			t.Errorf("componentType(%q) = %q, want application", ty, got)
		}
	}
	libs := []artifact.Type{artifact.TypeSkill, artifact.TypeSubagent, artifact.TypeRules, artifact.TypeContext}
	for _, ty := range libs {
		if got := componentType(ty); got != "library" {
			t.Errorf("componentType(%q) = %q, want library", ty, got)
		}
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name string
		src  artifact.Source
		want string
	}{
		{"npm with version", artifact.Source{Kind: artifact.SourceNPM, Ref: "left-pad@1.3.0"}, "1.3.0"},
		{"npm scoped", artifact.Source{Kind: artifact.SourceNPM, Ref: "@scope/pkg@2.0.0"}, "2.0.0"},
		{"npm no version", artifact.Source{Kind: artifact.SourceNPM, Ref: "left-pad"}, ""},
		{"git short sha", artifact.Source{Kind: artifact.SourceGit, Ref: "0123456789abcdef"}, "0123456789ab"},
		{"git too short", artifact.Source{Kind: artifact.SourceGit, Ref: "0123456"}, ""},
		{"local", artifact.Source{Kind: artifact.SourceLocal, Ref: "/path"}, ""},
	}
	for _, tt := range tests {
		if got := version(tt.src); got != tt.want {
			t.Errorf("%s: version = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestPurl(t *testing.T) {
	tests := []struct {
		name string
		src  artifact.Source
		want string
	}{
		{"npm name+version", artifact.Source{Kind: artifact.SourceNPM, Ref: "left-pad@1.3.0"}, "pkg:npm/left-pad@1.3.0"},
		{"npm name only", artifact.Source{Kind: artifact.SourceNPM, Ref: "left-pad"}, "pkg:npm/left-pad"},
		{"npm empty ref", artifact.Source{Kind: artifact.SourceNPM, Ref: ""}, ""},
		{"non-npm git", artifact.Source{Kind: artifact.SourceGit, Ref: "abc"}, ""},
	}
	for _, tt := range tests {
		if got := purl(tt.src); got != tt.want {
			t.Errorf("%s: purl = %q, want %q", tt.name, got, tt.want)
		}
	}
}
