package finding

import (
	"strings"
	"testing"
)

func TestClawHubFingerprintMismatchCarriesBothHashes(t *testing.T) {
	f := ClawHubFingerprintMismatch("aaaa", "bbbb")
	if RuleClawHubFingerprintMismatch != "CLAWHUB-FINGERPRINT-MISMATCH" {
		t.Errorf("RuleClawHubFingerprintMismatch = %q", RuleClawHubFingerprintMismatch)
	}
	if f.RuleID != RuleClawHubFingerprintMismatch {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityHigh || f.OWASP != "ASK-02" || f.File != ".clawhub/origin.json" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, "aaaa") || !strings.Contains(f.Explanation, "bbbb") {
		t.Errorf("explanation must name recorded and actual hashes: %q", f.Explanation)
	}
}

func TestPipelineRulesIncludesClawHubFingerprintMismatch(t *testing.T) {
	for _, f := range PipelineRules() {
		if f.RuleID == RuleClawHubFingerprintMismatch {
			if f.Severity != SeverityHigh || f.Explanation == "" {
				t.Errorf("unexpected template %+v", f)
			}
			return
		}
	}
	t.Error("CLAWHUB-FINGERPRINT-MISMATCH missing from PipelineRules")
}
