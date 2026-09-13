package discover

import (
	"path/filepath"
	"strings"
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

func TestLoadManifestAbsentIsNotPresent(t *testing.T) {
	_, present, err := loadManifest(t.TempDir())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if present {
		t.Error("present = true for a root with no manifest")
	}
}

func TestLoadManifestParsesValidFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile),
		`{"version":1,"name":"venice-skills","skills":["skills/*"],"harvest":["scripts/*.sh"]}`)
	m, present, err := loadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("present = false")
	}
	if m.Name != "venice-skills" || len(m.Skills) != 1 || m.Skills[0] != "skills/*" || len(m.Harvest) != 1 {
		t.Errorf("manifest = %+v", m)
	}
}

// A committed manifest that is broken must fail the scan and name the field.
// Silently discovering nothing would let a typo disable the whole gate.
func TestLoadManifestRejectsBadFiles(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{"version 2", `{"version":2,"name":"x","skills":["skills/*"]}`, `"version" must be 1`},
		{"version missing", `{"name":"x","skills":["skills/*"]}`, `"version" must be 1`},
		{"name missing", `{"version":1,"skills":["skills/*"]}`, `"name" is required`},
		{"name uppercase", `{"version":1,"name":"Venice","skills":["skills/*"]}`, `"name"`},
		{"skills missing", `{"version":1,"name":"x"}`, `"skills" must not be empty`},
		{"skills empty", `{"version":1,"name":"x","skills":[]}`, `"skills" must not be empty`},
		{"skills absolute", `{"version":1,"name":"x","skills":["/abs"]}`, `"skills" entry "/abs"`},
		{"skills bad pattern", `{"version":1,"name":"x","skills":["skills/["]}`, `"skills" entry "skills/["`},
		{"harvest bad pattern", `{"version":1,"name":"x","skills":["."],"harvest":["["]}`, `"harvest" entry "["`},
		{"unknown field", `{"version":1,"name":"x","skill":["skills/*"]}`, `unknown field "skill"`},
		{"not json", `{`, ManifestFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, ManifestFile), tc.body)
			_, present, err := loadManifest(dir)
			if !present {
				t.Error("present = false; a file that exists is present even when broken")
			}
			if err == nil {
				t.Fatal("err = nil, want an error")
			}
			if !strings.Contains(err.Error(), ManifestFile) {
				t.Errorf("err %q does not name %s", err, ManifestFile)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
