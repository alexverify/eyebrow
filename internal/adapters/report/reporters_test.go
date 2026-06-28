package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

func fixtureLockfile() lockfile.Lockfile {
	a := artifact.Artifact{
		ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "linter",
		ContentHash: "sha256-x",
		Findings: []finding.Finding{
			{RuleID: "RCE", Severity: finding.SeverityCritical, File: "run.sh", Line: 3},
			{RuleID: "NET", Severity: finding.SeverityLow},
		},
	}
	b := artifact.Artifact{ID: "a2", Tool: "cursor", Type: artifact.TypeMCPServer, Name: "db"}
	return lockfile.Build([]artifact.Artifact{a, b}, time.Unix(0, 0).UTC(), "t")
}

func TestJSONScanIsValidAndRoundTrips(t *testing.T) {
	lf := fixtureLockfile()
	var buf bytes.Buffer
	if err := (JSON{}).Scan(&buf, lf); err != nil {
		t.Fatal(err)
	}
	var got lockfile.Lockfile
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Scan output is not valid JSON: %v", err)
	}
	if len(got.Artifacts) != 2 {
		t.Errorf("round-tripped artifacts = %d, want 2", len(got.Artifacts))
	}
}

func TestJSONListEmitsArtifactArray(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSON{}).List(&buf, fixtureLockfile()); err != nil {
		t.Fatal(err)
	}
	var arts []artifact.Artifact
	if err := json.Unmarshal(buf.Bytes(), &arts); err != nil {
		t.Fatalf("List output is not a JSON array of artifacts: %v", err)
	}
	if len(arts) != 2 {
		t.Errorf("listed artifacts = %d, want 2", len(arts))
	}
}

func TestJSONVerify(t *testing.T) {
	var buf bytes.Buffer
	d := lockfile.Diff{Changes: []lockfile.Change{{Kind: lockfile.DriftContentChanged, ID: "a1", Name: "linter"}}}
	if err := (JSON{}).Verify(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("Verify output is not valid JSON:\n%s", buf.String())
	}
}

func TestTextScanShowsCountsAndFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (Text{}).Scan(&buf, fixtureLockfile()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"2 artifact(s)", "linter", "critical=1", "RCE", "run.sh:3", "findings: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("Scan output missing %q:\n%s", want, out)
		}
	}
}

func TestTextVerifyClean(t *testing.T) {
	var buf bytes.Buffer
	if err := (Text{}).Verify(&buf, lockfile.Diff{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no drift") {
		t.Errorf("clean verify should report no drift:\n%s", buf.String())
	}
}

func TestTextVerifyDrift(t *testing.T) {
	var buf bytes.Buffer
	d := lockfile.Diff{Changes: []lockfile.Change{
		{Kind: lockfile.DriftVersionChanged, ID: "a1", Name: "linter", Old: "1.0.0", New: "1.1.0"},
	}}
	if err := (Text{}).Verify(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"DRIFT", "1 change(s)", "linter", "old: 1.0.0", "new: 1.1.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift verify missing %q:\n%s", want, out)
		}
	}
}
