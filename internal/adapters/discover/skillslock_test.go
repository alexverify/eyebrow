package discover

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Repos in the skills-lock ecosystem (dexter-mcp, solana-foundation/pay) keep
// their catalog at a top-level skills/<slug>/SKILL.md and declare it with a
// skills-lock.json at the root. The adapter activates only on that marker, so
// it stays inert for every other repo with a skills/ directory.
func TestSkillsLockDiscoversSkillsWhenMarkerPresent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, "skills", "pay", "SKILL.md"),
		"---\nname: pay\ndescription: paid API access\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "skills", "x402-protocol", "SKILL.md"),
		"---\nname: x402-protocol\ndescription: protocol reference\n---\nbody\n")

	s := NewSkillsLock()
	if s.Tool() != "skills-lock" {
		t.Fatalf("Tool() = %q, want skills-lock", s.Tool())
	}
	got, err := s.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if len(m) != 2 {
		t.Fatalf("discovered %d skills, want 2: %+v", len(m), got)
	}
	pay := m["pay"]
	if pay.Type != artifact.TypeSkill {
		t.Errorf("pay type = %q, want skill", pay.Type)
	}
	if pay.Tool != "skills-lock" {
		t.Errorf("pay tool = %q, want skills-lock", pay.Tool)
	}
	if pay.Source.Kind != artifact.SourceLocal {
		t.Errorf("pay source kind = %q, want local", pay.Source.Kind)
	}
	if pay.ID == "" {
		t.Errorf("pay has no ID: %+v", pay)
	}
}

// Egress fingerprinting matches the AEON adapter: hosts on an actual
// network-call line become the skill's Network capability; a host that only
// appears in prose must not count.
func TestSkillsLockExtractsEgressCapabilityFromCallLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, "skills", "pay", "SKILL.md"), strings.Join([]string{
		"---", "name: pay", "description: paid API access", "---",
		"Docs live at https://docs.example.com/pay for background.", // prose — must NOT count
		"Run `curl https://api.dexter.cash/v1/quote` to fetch a quote.",
	}, "\n")+"\n")

	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	caps := byName(got)["pay"].Capabilities
	want := []string{"api.dexter.cash"}
	if !reflect.DeepEqual(caps.Network, want) {
		t.Errorf("Network = %v, want %v (docs.example.com must be excluded)", caps.Network, want)
	}
}

// Without the skills-lock.json marker the adapter must find nothing, even with
// the skills/ layout present — a plain skills/ directory elsewhere must not get
// artifacts injected into its scan.
func TestSkillsLockInertWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills", "pay", "SKILL.md"),
		"---\nname: pay\ndescription: paid API access\n---\nbody\n")

	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("discovered %d artifacts without skills-lock.json marker, want 0: %+v", len(got), got)
	}
}

// dexter-mcp keeps the pay skill's single source at .agents/skills/pay and
// symlinks skills/pay to it. A symlinked skill directory is part of the
// catalog and must be discovered — os.ReadDir reports a symlink entry as
// not-a-dir, so the helper has to resolve it before deciding.
func TestSkillsLockDiscoversSymlinkedSkillDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, ".agents", "skills", "pay", "SKILL.md"),
		"---\nname: pay\ndescription: paid API access\n---\nbody\n")
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", ".agents", "skills", "pay"), filepath.Join(dir, "skills", "pay")); err != nil {
		t.Skipf("symlinks unavailable: %v", err) // e.g. Windows without privilege
	}

	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, ok := byName(got)["pay"]; !ok {
		t.Fatalf("symlinked skills/pay not discovered: %+v", got)
	}
}

// AEON repos carry both an aeon.yml and (potentially) a skills-lock.json-free
// layout; a repo carrying BOTH markers would double-report every skill under
// two tool ids. The AEON marker wins: skills-lock stays inert when aeon.yml is
// present.
func TestSkillsLockYieldsToAeonMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, "skills", "pay", "SKILL.md"),
		"---\nname: pay\ndescription: paid API access\n---\nbody\n")

	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("discovered %d artifacts despite aeon.yml marker, want 0 (AEON adapter owns the layout): %+v", len(got), got)
	}
}

// Same rule as AEON: a manifest at the root owns the catalog.
func TestSkillsLockYieldsToManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{\"version\":1,\"skills\":{}}\n")
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"x","skills":["skills/*"]}`)
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("skills-lock reported %d skills next to a manifest, want 0", len(got))
	}
}
