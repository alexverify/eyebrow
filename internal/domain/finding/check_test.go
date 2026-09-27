package finding

import (
	"strings"
	"testing"
)

func TestUnscannedFileNamesTheFileAndReason(t *testing.T) {
	f := UnscannedFile("dist/blob.bin", "binary content")
	if RuleUnscannedFile != "CHECK-UNSCANNED-FILE" {
		t.Errorf("RuleUnscannedFile = %q", RuleUnscannedFile)
	}
	if f.RuleID != RuleUnscannedFile {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityMedium || f.OWASP != "ASK-02" || f.File != "dist/blob.bin" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, "binary content") {
		t.Errorf("explanation must name the reason: %q", f.Explanation)
	}
	if f.Snippet != "" || f.Line != 0 {
		t.Errorf("finding must carry no content: %+v", f)
	}
}

func TestUnsafeEntryNamesTheEntryAndReason(t *testing.T) {
	f := UnsafeEntry("link.md", "symlink pointing outside the folder")
	if RuleUnsafeEntry != "CHECK-UNSAFE-ENTRY" {
		t.Errorf("RuleUnsafeEntry = %q", RuleUnsafeEntry)
	}
	if f.RuleID != RuleUnsafeEntry {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != SeverityHigh || f.OWASP != "ASK-02" || f.File != "link.md" {
		t.Errorf("unexpected shape %+v", f)
	}
	if !strings.Contains(f.Explanation, "symlink pointing outside the folder") {
		t.Errorf("explanation must name the reason: %q", f.Explanation)
	}
	if f.Snippet != "" || f.Line != 0 {
		t.Errorf("finding must carry no content: %+v", f)
	}
}
