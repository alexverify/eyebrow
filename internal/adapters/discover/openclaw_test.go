package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

func writeOpenClawPlugin(t *testing.T, dir, desc string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "openclaw.plugin.json"), `{"id":"`+filepath.Base(dir)+`","description":"`+desc+`"}`)
	writeFile(t, filepath.Join(dir, "index.js"), "export default {}\n")
}

// The global scope reads the state dir: openclaw.json (JSON5) for MCP servers
// and extra skill roots, skills/ for managed skills, extensions/ for plugins.
func TestOpenClawDiscoversGlobalState(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".openclaw")
	writeFile(t, filepath.Join(state, "openclaw.json"), `{
		// OpenClaw config is JSON5
		mcp: {
			servers: {
				docs: { command: 'uvx', args: ['mcp-server-fetch'], },
				remote: { url: 'https://example.com/mcp', transport: 'streamable-http' },
			},
		},
		skills: { load: { extraDirs: ['~/agent-scripts/skills'] } },
	}`)
	writeFile(t, filepath.Join(state, "skills", "managed", "SKILL.md"), "---\ndescription: managed skill\n---\n")
	writeFile(t, filepath.Join(home, "agent-scripts", "skills", "extra", "SKILL.md"), "---\ndescription: extra skill\n---\n")
	writeOpenClawPlugin(t, filepath.Join(state, "extensions", "voice-call"), "Voice calls")
	// A folder without a plugin manifest is not a plugin.
	writeFile(t, filepath.Join(state, "extensions", "junk", "readme.txt"), "x")

	o := &OpenClaw{home: home, stateDir: state}
	if o.Tool() != "openclaw" {
		t.Fatalf("Tool() = %q", o.Tool())
	}
	arts, err := o.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(arts)
	if len(arts) != 5 {
		t.Errorf("want 5 artifacts, got %d: %+v", len(arts), arts)
	}
	if a := m["docs"]; a.Type != artifact.TypeMCPServer || a.Tool != "openclaw" || a.Scope != "global" {
		t.Errorf("docs server wrong: %+v", a)
	}
	if a := m["remote"]; a.Type != artifact.TypeMCPServer || a.Source.Kind != artifact.SourceURL {
		t.Errorf("remote server wrong: %+v", a)
	}
	if a := m["managed"]; a.Type != artifact.TypeSkill || a.Description != "managed skill" {
		t.Errorf("managed skill wrong: %+v", a)
	}
	if a := m["extra"]; a.Type != artifact.TypeSkill || a.Description != "extra skill" {
		t.Errorf("extraDirs skill wrong: %+v", a)
	}
	p := m["voice-call"]
	if p.Type != artifact.TypePlugin || p.Description != "Voice calls" || p.Source.Kind != artifact.SourceLocal ||
		p.Source.Ref != filepath.Join(state, "extensions", "voice-call") {
		t.Errorf("plugin wrong: %+v", p)
	}
}

// OPENCLAW_STATE_DIR moves the whole state dir.
func TestOpenClawHonorsStateDirEnv(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("OPENCLAW_STATE_DIR", custom)
	writeFile(t, filepath.Join(custom, "skills", "moved", "SKILL.md"), "---\n---\n")
	o := NewOpenClaw()
	arts, err := o.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byName(arts)["moved"]; !ok {
		t.Errorf("skill under OPENCLAW_STATE_DIR not found: %+v", arts)
	}
}

// A project is OpenClaw's only when it carries .openclaw/ or .clawhub/; a
// plain skills/ folder belongs to other tools.
func TestOpenClawProjectGate(t *testing.T) {
	plain := t.TempDir()
	writeFile(t, filepath.Join(plain, "skills", "s", "SKILL.md"), "---\n---\n")

	marked := t.TempDir()
	writeFile(t, filepath.Join(marked, "skills", "s", "SKILL.md"), "---\n---\n")
	writeFile(t, filepath.Join(marked, ".clawhub", "lock.json"), `{"version":1,"skills":{}}`)

	ext := t.TempDir()
	writeOpenClawPlugin(t, filepath.Join(ext, ".openclaw", "extensions", "local-plugin"), "Local")

	o := &OpenClaw{home: t.TempDir(), stateDir: t.TempDir()}
	arts, err := o.Discover(context.Background(), []ports.Scope{
		{Kind: "project", Path: plain},
		{Kind: "project", Path: marked},
		{Kind: "project", Path: ext},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("want 2 artifacts (marked skill + local plugin), got %+v", arts)
	}
	m := byName(arts)
	if a := m["s"]; a.Scope != (ports.Scope{Kind: "project", Path: marked}).String() {
		t.Errorf("skill scope wrong: %+v", a)
	}
	if a := m["local-plugin"]; a.Type != artifact.TypePlugin {
		t.Errorf("project plugin wrong: %+v", a)
	}
}

// Skills installed from ClawHub carry their origin fingerprint as integrity
// anchor; a modified one raises a mismatch finding.
func TestOpenClawAppliesClawHubPins(t *testing.T) {
	state := t.TempDir()
	skill := filepath.Join(state, "skills", "demo")
	writeClawHubFixture(t, skill)
	writeOrigin(t, skill, fixtureClawHubFingerprint)
	writeFile(t, filepath.Join(skill, "references", "a.md"), "B\n")

	o := &OpenClaw{home: t.TempDir(), stateDir: state}
	arts, err := o.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatal(err)
	}
	a := byName(arts)["demo"]
	if a.Source.Integrity != "sha256-"+fixtureClawHubFingerprint {
		t.Errorf("Integrity = %q", a.Source.Integrity)
	}
	if len(a.Findings) != 1 || a.Findings[0].RuleID != finding.RuleClawHubFingerprintMismatch {
		t.Errorf("want mismatch finding, got %+v", a.Findings)
	}
}

// Nothing installed is not an error, and a broken config yields nothing.
func TestOpenClawAbsentOrBrokenIsQuiet(t *testing.T) {
	state := t.TempDir()
	writeFile(t, filepath.Join(state, "openclaw.json"), `{ mcp: `)
	o := &OpenClaw{home: t.TempDir(), stateDir: state}
	arts, err := o.Discover(context.Background(), []ports.Scope{{Kind: "global"}, {Kind: "project", Path: t.TempDir()}})
	if err != nil || len(arts) != 0 {
		t.Errorf("want nothing, got %+v, err %v", arts, err)
	}
}
