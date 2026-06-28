package artifact

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/finding"
)

func TestMakeIDStable(t *testing.T) {
	a := MakeID("claude-code", "user", TypeSkill, "deploy")
	b := MakeID("claude-code", "user", TypeSkill, "deploy")
	if a != b {
		t.Fatalf("MakeID not stable: %q != %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("MakeID length = %d, want 16", len(a))
	}
}

func TestMakeIDDistinguishesEveryField(t *testing.T) {
	base := MakeID("claude-code", "user", TypeSkill, "deploy")
	others := map[string]string{
		"tool":  MakeID("cursor", "user", TypeSkill, "deploy"),
		"scope": MakeID("claude-code", "project", TypeSkill, "deploy"),
		"type":  MakeID("claude-code", "user", TypeMCPServer, "deploy"),
		"name":  MakeID("claude-code", "user", TypeSkill, "release"),
	}
	for field, id := range others {
		if id == base {
			t.Errorf("MakeID collides when %s differs", field)
		}
	}
}

// A naive concatenation without delimiters would collide here; the NUL
// separator must keep these distinct.
func TestMakeIDDelimiterPreventsCollision(t *testing.T) {
	if MakeID("ab", "c", TypeSkill, "d") == MakeID("a", "bc", TypeSkill, "d") {
		t.Error("MakeID collides across a shifted field boundary")
	}
}

func TestMaxSeverity(t *testing.T) {
	empty := Artifact{}
	if got := empty.MaxSeverity(); got != finding.SeverityInfo {
		t.Errorf("MaxSeverity(no findings) = %q, want %q", got, finding.SeverityInfo)
	}
	a := Artifact{Findings: []finding.Finding{
		{Severity: finding.SeverityLow},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityMedium},
	}}
	if got := a.MaxSeverity(); got != finding.SeverityHigh {
		t.Errorf("MaxSeverity = %q, want %q", got, finding.SeverityHigh)
	}
}
