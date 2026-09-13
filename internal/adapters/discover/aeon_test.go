package discover

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// AEON keeps its skills at a top-level skills/<slug>/SKILL.md — not under
// .claude/skills. The adapter activates only when it sees AEON's aeon.yml
// marker, so it stays inert for every other repo.
func TestAeonDiscoversSkillsWhenMarkerPresent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills", "token-movers", "SKILL.md"),
		"---\nname: token-movers\ndescription: moves tokens\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "skills", "okf-ingest", "SKILL.md"),
		"---\nname: okf-ingest\ndescription: ingests knowledge\n---\nbody\n")

	a := NewAeon()
	if a.Tool() != "aeon" {
		t.Fatalf("Tool() = %q, want aeon", a.Tool())
	}
	got, err := a.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if len(m) != 2 {
		t.Fatalf("discovered %d skills, want 2: %+v", len(m), got)
	}
	tm := m["token-movers"]
	if tm.Type != artifact.TypeSkill {
		t.Errorf("token-movers type = %q, want skill", tm.Type)
	}
	if tm.Tool != "aeon" {
		t.Errorf("token-movers tool = %q, want aeon", tm.Tool)
	}
	if tm.Source.Kind != artifact.SourceLocal {
		t.Errorf("token-movers source kind = %q, want local", tm.Source.Kind)
	}
	if tm.ID == "" {
		t.Errorf("token-movers has no ID: %+v", tm)
	}
}

// The adapter fingerprints each skill's egress: hosts reached from an actual
// network-call line (./secretcurl, curl, wget, WebFetch) become the skill's
// Network capability. A host that only appears in prose (a doc link) must not
// count — that keeps the capability-expansion gate low-noise.
func TestAeonExtractsEgressCapabilityFromCallLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills", "price", "SKILL.md"), strings.Join([]string{
		"---", "name: price", "description: quotes", "---",
		"See docs at https://docs.example.com/guide for background.", // prose — must NOT count
		"Network note: `./secretcurl https://api.coingecko.com/v3/price`",
		"Then `curl https://hooks.slack.com/services/x` to post.",
	}, "\n")+"\n")

	got, err := NewAeon().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	caps := byName(got)["price"].Capabilities
	want := []string{"api.coingecko.com", "hooks.slack.com"}
	if !reflect.DeepEqual(caps.Network, want) {
		t.Errorf("Network = %v, want %v (docs.example.com must be excluded)", caps.Network, want)
	}
}

// Without the aeon.yml marker the adapter must find nothing, even though the
// skills/ layout is present — otherwise any repo with a skills/ dir would get
// AEON artifacts injected into its scan.
func TestAeonInertWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills", "token-movers", "SKILL.md"),
		"---\nname: token-movers\ndescription: moves tokens\n---\nbody\n")

	got, err := NewAeon().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("discovered %d artifacts without aeon.yml marker, want 0: %+v", len(got), got)
	}
}

// When a root carries eyebrow.discover.json the declared adapter owns it,
// and the AEON adapter stays inert even though aeon.yml is present.
func TestAeonYieldsToManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, ManifestFile), `{"version":1,"name":"x","skills":["skills/*"]}`)
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
	got, err := NewAeon().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("aeon reported %d skills next to a manifest, want 0", len(got))
	}
}
