package dashboard

import (
	"strings"

	"github.com/alexverify/assay/internal/domain/finding"
)

// ruleInfo gives a finding rule the two presentation fields the dashboard
// shows that the domain Finding doesn't carry: a coarse pattern category and a
// short human title. The domain Explanation becomes the longer detail.
type ruleInfo struct {
	pattern string
	title   string
}

// rules maps native analyzer rule IDs to their dashboard pattern + title.
// Patterns intentionally match the dashboard's six categories.
var rules = map[string]ruleInfo{
	"RCE-PIPE-EXEC":         {"remote-code-exec", "Pipes a remote script into a shell"},
	"RCE-POWERSHELL-IEX":    {"remote-code-exec", "Executes a downloaded PowerShell payload"},
	"REVERSE-SHELL":         {"remote-code-exec", "Opens a reverse shell"},
	"EXEC-PRIMITIVE":        {"command-exec", "Spawns shell commands"},
	"NPM-INSTALL-HOOK":      {"command-exec", "Runs code from an npm install hook"},
	"ENCODED-EXEC":          {"command-exec", "Executes encoded/obfuscated code"},
	"OBFUSCATION-EVAL":      {"command-exec", "Evaluates dynamically-built code"},
	"EXFIL-SUSPICIOUS-HOST": {"data-exfil", "Sends data to a suspicious host"},
	"WALLET-THEFT":          {"data-exfil", "Accesses wallet or browser secrets"},
	"SSRF-CLOUD-METADATA":   {"ssrf", "Reaches the cloud metadata endpoint"},
	"SENSITIVE-PATH-READ":   {"secret-access", "Reads sensitive credential paths"},
	"PROMPT-INJECTION":      {"consent-bypass", "Prompt-injection / consent-bypass language"},
}

// patternOf returns the dashboard pattern for a rule ID, defaulting sensibly
// for Semgrep and unknown rules.
func patternOf(ruleID string) string {
	if r, ok := rules[ruleID]; ok {
		return r.pattern
	}
	switch {
	case strings.Contains(ruleID, "EXFIL"), strings.Contains(ruleID, "WALLET"):
		return "data-exfil"
	case strings.Contains(ruleID, "SSRF"):
		return "ssrf"
	case strings.Contains(ruleID, "RCE"), strings.Contains(ruleID, "SHELL"):
		return "remote-code-exec"
	case strings.Contains(ruleID, "SECRET"), strings.Contains(ruleID, "PATH"):
		return "secret-access"
	default:
		return "command-exec"
	}
}

// titleOf returns a short human title, preferring the curated map and falling
// back to the rule's own explanation or ID.
func titleOf(f finding.Finding) string {
	if r, ok := rules[f.RuleID]; ok {
		return r.title
	}
	if f.Explanation != "" {
		return f.Explanation
	}
	return f.RuleID
}
