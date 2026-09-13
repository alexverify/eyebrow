package discover

import (
	"path/filepath"
	"testing"
)

// The declared adapter names a root-level skill from its frontmatter, so the
// frontmatter reader has to take the key as a parameter.
func TestFrontmatterValueReadsAnyTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "SKILL.md")
	writeFile(t, p, "---\nname: sibyl-save\ndescription: \"saves memory\"\n---\nbody\n")
	if got := frontmatterValue(p, "name"); got != "sibyl-save" {
		t.Errorf("name = %q, want sibyl-save", got)
	}
	if got := frontmatterValue(p, "description"); got != "saves memory" {
		t.Errorf("description = %q, want saves memory", got)
	}
	if got := frontmatterValue(p, "missing"); got != "" {
		t.Errorf("missing key = %q, want empty", got)
	}
	if got := frontmatterDescription(p); got != "saves memory" {
		t.Errorf("frontmatterDescription = %q, want saves memory", got)
	}
}
