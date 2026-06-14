// Package advisory matches discovered artifacts against a curated, offline feed
// of known-malicious skills and MCP servers. A match is the highest-confidence
// signal assay can make: not a heuristic, but a hit against ground truth
// (e.g. the postmark-mcp BCC-exfiltration campaign).
//
// Like the rest of the domain core, it is pure: no IO, no third-party imports.
// The feed is embedded so it works fully offline; a future opt-in pull can
// replace Default() with a refreshed, signed list.
package advisory

import (
	"strings"

	"github.com/alexverify/assay/internal/domain/finding"
)

// Advisory is one known-malicious indicator. Each non-empty field is a
// condition; all non-empty fields must match (AND). Matching is
// case-insensitive. An advisory with no conditions never matches.
type Advisory struct {
	ID             string // stable id, e.g. "postmark-mcp-bcc"
	Title          string // short headline
	Reason         string // what it does / why it is dangerous
	NameContains   string // substring of the artifact name
	SourceContains string // substring of the source ref
	ContentHash    string // exact content hash match
}

// AsFinding renders the advisory as a critical, OWASP-mapped finding so it flows
// through the same reporting, policy gate, and dashboard as any other finding.
func (adv Advisory) AsFinding() finding.Finding {
	return finding.Finding{
		RuleID:      "ADVISORY-" + adv.ID,
		Severity:    finding.SeverityCritical,
		OWASP:       "AST01",
		Explanation: adv.Title + " — " + adv.Reason,
	}
}

// Match returns every advisory in advs that matches the artifact identity.
func Match(advs []Advisory, name, source, contentHash string) []Advisory {
	name = strings.ToLower(name)
	source = strings.ToLower(source)
	contentHash = strings.ToLower(contentHash)
	var out []Advisory
	for _, adv := range advs {
		if adv.matches(name, source, contentHash) {
			out = append(out, adv)
		}
	}
	return out
}

// matches reports whether every condition the advisory declares is satisfied.
// Inputs are already lowercased by Match.
func (adv Advisory) matches(name, source, contentHash string) bool {
	any := false
	if adv.NameContains != "" {
		any = true
		if !strings.Contains(name, strings.ToLower(adv.NameContains)) {
			return false
		}
	}
	if adv.SourceContains != "" {
		any = true
		if !strings.Contains(source, strings.ToLower(adv.SourceContains)) {
			return false
		}
	}
	if adv.ContentHash != "" {
		any = true
		if contentHash != strings.ToLower(adv.ContentHash) {
			return false
		}
	}
	return any
}

// Default is the embedded, curated advisory feed. Each entry corresponds to a
// documented real-world incident.
func Default() []Advisory {
	return []Advisory{
		{
			ID:           "postmark-mcp-bcc",
			Title:        "postmark-mcp email exfiltration",
			Reason:       "v1.0.16 of the postmark-mcp npm package silently BCC'd every email to an attacker domain (Koi Security, Sept 2025).",
			NameContains: "postmark-mcp",
		},
		{
			ID:             "giftshop-club-exfil",
			Title:          "known exfiltration endpoint",
			Reason:         "giftshop.club was the drop site for the postmark-mcp BCC campaign.",
			SourceContains: "giftshop.club",
		},
		{
			ID:             "clawhavoc-wallet-stealer",
			Title:          "ClawHavoc wallet/credential stealer",
			Reason:         "skills in this cluster POST browser-profile and wallet directories to an external host and rewrite agent memory to persist.",
			SourceContains: "collect.cf-pages.io",
		},
	}
}
