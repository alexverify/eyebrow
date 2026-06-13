package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

func TestTextListIncludesTrustVerdict(t *testing.T) {
	clean := artifact.Artifact{
		ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "linter",
		ContentHash: "sha256-x",
		Source:      artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"},
	}
	risky := artifact.Artifact{
		ID: "a2", Tool: "cursor", Type: artifact.TypeMCPServer, Name: "db",
		ContentHash: "sha256-y",
		Source:      artifact.Source{Kind: artifact.SourceNPM, Ref: "0.1.0"}, // no integrity → unpinned
		Findings:    []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical}},
	}
	lf := lockfile.Build([]artifact.Artifact{clean, risky}, time.Unix(0, 0).UTC(), "t")

	var buf bytes.Buffer
	if err := (Text{}).List(&buf, lf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "trusted") {
		t.Errorf("clean artifact should print trusted verdict:\n%s", out)
	}
	if !strings.Contains(out, "quarantine") {
		t.Errorf("critical+unpinned artifact should print quarantine verdict:\n%s", out)
	}
}
