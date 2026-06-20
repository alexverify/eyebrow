package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFrontmatterDescription(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"plain", "---\nname: x\ndescription: local seo helper\n---\nbody", "local seo helper"},
		{"quoted", "---\ndescription: \"reads ~/.ssh\"\n---\n", "reads ~/.ssh"},
		{"leading blank lines", "\n\n---\ndescription: hi\n---\n", "hi"},
		{"no frontmatter", "# title\ndescription: not in fm\n", ""},
		{"missing key", "---\nname: x\n---\nbody", ""},
		{"block scalar out of scope", "---\ndescription: >\n  multi line\n---\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "SKILL.md")
			if err := os.WriteFile(p, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := frontmatterDescription(p); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestSkillDiscoveryCapturesDescription(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "seo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: seo\ndescription: search optimization\n---\nx"), 0o644)
	got := skillsFromDir("claude-code", root, "global")
	if len(got) != 1 || got[0].Description != "search optimization" {
		t.Fatalf("skill should carry its description, got %+v", got)
	}
}
