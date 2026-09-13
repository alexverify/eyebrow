package discover

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
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

func TestDeclaredInertWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("discovered %d artifacts without a manifest, want 0", len(got))
	}
}

func TestDeclaredDiscoversGlobCatalog(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"venice-skills","skills":["skills/*"]}`)
	writeFile(t, filepath.Join(dir, "skills", "trade", "SKILL.md"), "---\nname: trade\ndescription: trades\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "skills", "quote", "SKILL.md"), "---\nname: quote\ndescription: quotes\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "skills", "notes", "README.md"), "no SKILL.md here\n")
	writeFile(t, filepath.Join(dir, "skills", "loose.md"), "a file, not a dir\n")

	d := NewDeclared()
	if d.Tool() != "declared" {
		t.Fatalf("Tool() = %q, want declared", d.Tool())
	}
	sc := ports.Scope{Kind: "project", Path: dir}
	got, err := d.Discover(context.Background(), []ports.Scope{sc})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(got)
	if len(m) != 2 {
		t.Fatalf("discovered %d skills, want 2: %+v", len(m), got)
	}
	tr := m["trade"]
	if tr.Tool != "venice-skills" {
		t.Errorf("tool = %q, want the manifest name", tr.Tool)
	}
	if tr.Type != artifact.TypeSkill {
		t.Errorf("type = %q, want skill", tr.Type)
	}
	if tr.Scope != sc.String() {
		t.Errorf("scope = %q, want %q", tr.Scope, sc.String())
	}
	if tr.Source.Kind != artifact.SourceLocal || tr.Source.Ref != filepath.Join(dir, "skills", "trade") {
		t.Errorf("source = %+v, want local ref to the skill dir", tr.Source)
	}
	if tr.DiscoveredFrom != filepath.Join(dir, "skills", "trade", "SKILL.md") {
		t.Errorf("discoveredFrom = %q", tr.DiscoveredFrom)
	}
	if tr.Description != "trades" {
		t.Errorf("description = %q, want trades", tr.Description)
	}
	if tr.ID != artifact.MakeID("venice-skills", sc.String(), artifact.TypeSkill, "trade") {
		t.Errorf("id = %q, not MakeID(tool, scope, type, name)", tr.ID)
	}
}

func TestDeclaredProjectScopeOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"x","skills":["."]}`)
	writeFile(t, filepath.Join(dir, "SKILL.md"), "---\nname: x\n---\n")
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "global"}, {Kind: "registry", Path: "https://r"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("discovered %d artifacts outside project scope, want 0", len(got))
	}
}

// "." declares the whole checkout as one skill: companion scripts included,
// the way Sibyl's sibyl-save and debloat ship. Name comes from frontmatter.
func TestDeclaredRootSkillNamedFromFrontmatter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"sibyl","skills":["."]}`)
	writeFile(t, filepath.Join(dir, "SKILL.md"), "---\nname: sibyl-save\ndescription: saves memory\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "watermark.mjs"), "export {}\n")
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d, want 1: %+v", len(got), got)
	}
	a := got[0]
	if a.Name != "sibyl-save" {
		t.Errorf("name = %q, want sibyl-save (from frontmatter)", a.Name)
	}
	if a.Source.Ref != filepath.Clean(dir) {
		t.Errorf("source ref = %q, want the repo root %q", a.Source.Ref, dir)
	}
}

func TestDeclaredRootSkillFallsBackToDirName(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "debloat")
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"sibyl","skills":["."]}`)
	writeFile(t, filepath.Join(dir, "SKILL.md"), "no frontmatter\n")
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "debloat" {
		t.Errorf("got %+v, want one skill named debloat", got)
	}
}

// Two globs matching the same directory report it once.
func TestDeclaredDedupesOverlappingGlobs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"x","skills":["skills/*","skills/a"]}`)
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("discovered %d, want 1: %+v", len(got), got)
	}
}

// dexter-mcp symlinks skills/pay to .agents/skills/pay. A symlinked skill
// directory is part of the catalog and must be discovered.
func TestDeclaredFollowsSymlinkedSkillDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"x","skills":["skills/*"]}`)
	writeFile(t, filepath.Join(dir, ".agents", "skills", "pay", "SKILL.md"), "---\nname: pay\n---\n")
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", ".agents", "skills", "pay"), filepath.Join(dir, "skills", "pay")); err != nil {
		t.Skipf("symlinks unavailable: %v", err) // e.g. Windows without privilege
	}
	got, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "pay" {
		t.Errorf("got %+v, want one skill named pay", got)
	}
}

// A broken manifest is an error from Discover, so scan fails instead of
// quietly reporting nothing.
func TestDeclaredBrokenManifestFailsDiscover(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"skills":["skills/*"]}`)
	_, err := NewDeclared().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err == nil || !strings.Contains(err.Error(), `"name" is required`) {
		t.Errorf("err = %v, want the validation error", err)
	}
}

// The manifest name is the tool id, so a repo moving from the AEON adapter to
// a manifest named "aeon" keeps every lockfile ID.
func TestDeclaredNamedAeonKeepsAeonIDs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills", "token-movers", "SKILL.md"), "---\nname: token-movers\n---\n")
	sc := ports.Scope{Kind: "project", Path: dir}
	viaAeon, err := NewAeon().Discover(context.Background(), []ports.Scope{sc})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"aeon","skills":["skills/*"]}`)
	viaManifest, err := NewDeclared().Discover(context.Background(), []ports.Scope{sc})
	if err != nil {
		t.Fatal(err)
	}
	if len(viaAeon) != 1 || len(viaManifest) != 1 {
		t.Fatalf("aeon=%d manifest=%d, want 1 each", len(viaAeon), len(viaManifest))
	}
	if viaAeon[0].ID != viaManifest[0].ID {
		t.Errorf("id via aeon = %s, via manifest = %s; must match", viaAeon[0].ID, viaManifest[0].ID)
	}
}
