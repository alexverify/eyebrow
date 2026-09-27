package discover

import (
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// ClawHub writes a fingerprint into <skill>/.clawhub/origin.json at install:
// files under the skill (dot segments and node_modules skipped) sorted by
// relative path with JavaScript localeCompare, then sha256 over the lines
// "path:sha256hex" joined by "\n". These values were produced under node by
// reproducing clawhub's listSkillFiles and buildSkillFingerprint.
const (
	fixtureClawHubFingerprint        = "28cd69225d5af43f020652d5723e6acf8cb4406e24bb5cea1027c40d04e6ac4b"
	fixtureClawHubFingerprintEditedA = "855b2f2d4c6238b4298484585f4f11b92df4e94c8f53478ab1bf3c42b1b54bde"
)

func writeClawHubFixture(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "SKILL.md"), "---\nname: demo\ndescription: fixture\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "references", "a.md"), "A\n")
	writeFile(t, filepath.Join(dir, "templates", "run.sh"), "#!/bin/sh\necho hi\n")
	writeFile(t, filepath.Join(dir, "scripts", "Run.sh"), "x\n")
	writeFile(t, filepath.Join(dir, "scripts", "run-all.sh"), "y\n")
	writeFile(t, filepath.Join(dir, "node_modules", "x.js"), "ignored\n")
	writeFile(t, filepath.Join(dir, ".hidden"), "h\n")
}

func writeOrigin(t *testing.T, dir, fingerprint string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, ".clawhub", "origin.json"), `{
  "version": 1,
  "registry": "https://clawhub.ai",
  "slug": "demo",
  "installedVersion": "1.0.0",
  "installedAt": 1760000000000,
  "fingerprint": "`+fingerprint+`"
}`)
}

func TestClawHubFingerprintReproducesClawHub(t *testing.T) {
	dir := t.TempDir()
	writeClawHubFixture(t, dir)
	writeOrigin(t, dir, "ignored-by-hash")
	got, err := clawHubFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureClawHubFingerprint {
		t.Errorf("fingerprint = %s, want %s", got, fixtureClawHubFingerprint)
	}
	writeFile(t, filepath.Join(dir, "references", "a.md"), "B\n")
	if got, _ := clawHubFingerprint(dir); got != fixtureClawHubFingerprintEditedA {
		t.Errorf("edited fingerprint = %s, want %s", got, fixtureClawHubFingerprintEditedA)
	}
}

func skillArtifact(dir string) artifact.Artifact {
	return artifact.Artifact{
		Type:           artifact.TypeSkill,
		Name:           filepath.Base(dir),
		Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: dir},
		DiscoveredFrom: filepath.Join(dir, "SKILL.md"),
	}
}

func TestClawHubPinAnchorsMatchingSkill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	writeClawHubFixture(t, dir)
	writeOrigin(t, dir, fixtureClawHubFingerprint)
	arts := []artifact.Artifact{skillArtifact(dir)}
	applyClawHubPins(arts)
	if arts[0].Source.Integrity != "sha256-"+fixtureClawHubFingerprint {
		t.Errorf("Integrity = %q", arts[0].Source.Integrity)
	}
	if len(arts[0].Findings) != 0 {
		t.Errorf("unexpected findings %+v", arts[0].Findings)
	}
}

func TestClawHubPinFlagsModifiedSkill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	writeClawHubFixture(t, dir)
	writeOrigin(t, dir, fixtureClawHubFingerprint)
	writeFile(t, filepath.Join(dir, "references", "a.md"), "B\n")
	arts := []artifact.Artifact{skillArtifact(dir)}
	applyClawHubPins(arts)
	if arts[0].Source.Integrity != "sha256-"+fixtureClawHubFingerprint {
		t.Errorf("anchor must stay the recorded value, got %q", arts[0].Source.Integrity)
	}
	if len(arts[0].Findings) != 1 || arts[0].Findings[0].RuleID != finding.RuleClawHubFingerprintMismatch {
		t.Fatalf("want one mismatch finding, got %+v", arts[0].Findings)
	}
}

// ClawHub also honors .gitignore and .clawhubignore, which eyebrow does not
// evaluate. A skill carrying either is left unpinned rather than risk a false
// mismatch.
func TestClawHubPinSkipsSkillWithIgnoreFile(t *testing.T) {
	for _, ignore := range []string{".gitignore", ".clawhubignore", ".clawdhubignore"} {
		dir := filepath.Join(t.TempDir(), "demo")
		writeClawHubFixture(t, dir)
		writeOrigin(t, dir, "0000000000000000000000000000000000000000000000000000000000000000")
		writeFile(t, filepath.Join(dir, ignore), "templates/\n")
		arts := []artifact.Artifact{skillArtifact(dir)}
		applyClawHubPins(arts)
		if arts[0].Source.Integrity != "" || len(arts[0].Findings) != 0 {
			t.Errorf("%s: skill must stay unpinned, got %+v", ignore, arts[0])
		}
	}
}

// Legacy installs wrote .clawdhub/origin.json; missing, malformed or
// fingerprint-less origins pin nothing.
func TestClawHubPinOriginVariants(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "demo")
	writeClawHubFixture(t, legacy)
	writeFile(t, filepath.Join(legacy, ".clawdhub", "origin.json"), `{"version":1,"fingerprint":"`+fixtureClawHubFingerprint+`"}`)
	// The legacy dot dir is itself skipped by the hash (dot segment).
	arts := []artifact.Artifact{skillArtifact(legacy)}
	applyClawHubPins(arts)
	if arts[0].Source.Integrity != "sha256-"+fixtureClawHubFingerprint || len(arts[0].Findings) != 0 {
		t.Errorf("legacy origin not honored: %+v", arts[0])
	}

	for name, body := range map[string]string{
		"malformed":      `{`,
		"no-fingerprint": `{"version":1}`,
		"not-hex":        `{"version":1,"fingerprint":"zz"}`,
	} {
		dir := filepath.Join(t.TempDir(), "demo")
		writeClawHubFixture(t, dir)
		writeFile(t, filepath.Join(dir, ".clawhub", "origin.json"), body)
		arts := []artifact.Artifact{skillArtifact(dir)}
		applyClawHubPins(arts)
		if arts[0].Source.Integrity != "" || len(arts[0].Findings) != 0 {
			t.Errorf("%s: must pin nothing, got %+v", name, arts[0])
		}
	}
}
