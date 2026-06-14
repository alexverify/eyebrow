package advisory

import (
	"testing"

	"github.com/alexverify/assay/internal/domain/finding"
)

func TestMatchByName(t *testing.T) {
	got := Match(Default(), "postmark-mcp", "npm:postmark-mcp@1.0.16", "sha256-x")
	if len(got) != 1 || got[0].ID != "postmark-mcp-bcc" {
		t.Fatalf("postmark-mcp should match the BCC advisory, got %+v", got)
	}
}

func TestMatchBySource(t *testing.T) {
	got := Match(Default(), "innocent-name", "https://giftshop.club/collect", "")
	if len(got) != 1 || got[0].ID != "giftshop-club-exfil" {
		t.Fatalf("giftshop.club source should match, got %+v", got)
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	got := Match(Default(), "Postmark-MCP", "", "")
	if len(got) != 1 {
		t.Fatalf("matching should be case-insensitive, got %+v", got)
	}
}

func TestNoMatchClean(t *testing.T) {
	got := Match(Default(), "markdown-linter", "github.com/tools/markdown-linter", "sha256-y")
	if len(got) != 0 {
		t.Fatalf("clean artifact must not match any advisory, got %+v", got)
	}
}

func TestEmptyAdvisoryNeverMatches(t *testing.T) {
	got := Match([]Advisory{{ID: "x"}}, "anything", "any-source", "any-hash")
	if len(got) != 0 {
		t.Fatalf("an advisory with no conditions must never match, got %+v", got)
	}
}

func TestAsFinding(t *testing.T) {
	f := Advisory{ID: "a", Title: "T", Reason: "R"}.AsFinding()
	if f.RuleID != "ADVISORY-a" {
		t.Errorf("ruleId = %q, want ADVISORY-a", f.RuleID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("advisory findings must be critical, got %q", f.Severity)
	}
	if f.OWASP != "AST01" {
		t.Errorf("owasp = %q, want AST01", f.OWASP)
	}
}
