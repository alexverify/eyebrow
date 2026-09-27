package finding

import "fmt"

// Rule ids for findings the scan pipeline raises without a pattern match.
// Reserving them here keeps them out of the native rule set's namespace and
// lets rule tables list them next to pattern rules.
const (
	// RuleSkillsLockMismatch: a skill named in skills-lock.json no longer
	// hashes to the folder hash the lock recorded.
	RuleSkillsLockMismatch = "SKILLS-LOCK-MISMATCH"
	// RuleClawHubFingerprintMismatch: a ClawHub-installed skill no longer
	// hashes to the fingerprint its .clawhub/origin.json recorded.
	RuleClawHubFingerprintMismatch = "CLAWHUB-FINGERPRINT-MISMATCH"
	// RuleResolveUnsupported: the source kind has no resolver yet.
	RuleResolveUnsupported = "RESOLVE-UNSUPPORTED"
	// RuleResolveFailed: resolving the source to verifiable code failed.
	RuleResolveFailed = "RESOLVE-FAILED"
)

// SkillsLockMismatch is the finding for a skill whose folder, hashed with the
// Vercel skills CLI's own algorithm, no longer matches the computedHash the
// project's skills-lock.json recorded for it.
func SkillsLockMismatch(recorded, actual string) Finding {
	f := skillsLockMismatch
	f.Explanation = fmt.Sprintf("skills-lock.json records sha256 %s for this skill but the folder hashes to %s under the skills CLI algorithm; the pinned content changed after the lock was written", recorded, actual)
	return f
}

// ClawHubFingerprintMismatch is the finding for a ClawHub-installed skill whose
// folder, hashed with ClawHub's own fingerprint algorithm, no longer matches
// the fingerprint recorded in its .clawhub/origin.json at install.
func ClawHubFingerprintMismatch(recorded, actual string) Finding {
	f := clawHubFingerprintMismatch
	f.Explanation = fmt.Sprintf(".clawhub/origin.json records fingerprint %s for this skill but the folder hashes to %s under the ClawHub algorithm; the installed content changed after install", recorded, actual)
	return f
}

// ResolveUnsupported is the finding recorded when a source kind cannot be
// resolved yet, so its integrity cannot be locked.
func ResolveUnsupported(kind string) Finding {
	f := resolveUnsupported
	f.Explanation = fmt.Sprintf("source kind %q cannot be resolved yet; its integrity cannot be locked", kind)
	return f
}

// ResolveFailed is the finding recorded when resolving a source fails outright.
func ResolveFailed(err error) Finding {
	f := resolveFailed
	f.Explanation = "could not resolve source to verifiable code: " + err.Error()
	return f
}

// PipelineRules lists one template per rule the pipeline raises without a
// pattern match, with a generic explanation for rule tables.
func PipelineRules() []Finding {
	return []Finding{LocalOutsideRoot(), skillsLockMismatch, clawHubFingerprintMismatch, resolveUnsupported, resolveFailed}
}

var (
	skillsLockMismatch = Finding{
		RuleID:      RuleSkillsLockMismatch,
		Severity:    SeverityHigh,
		OWASP:       "ASK-02",
		File:        "skills-lock.json",
		Explanation: "skills-lock.json records a folder hash for this skill that the folder no longer matches under the skills CLI algorithm",
	}
	clawHubFingerprintMismatch = Finding{
		RuleID:      RuleClawHubFingerprintMismatch,
		Severity:    SeverityHigh,
		OWASP:       "ASK-02",
		File:        ".clawhub/origin.json",
		Explanation: ".clawhub/origin.json records a fingerprint for this skill that the folder no longer matches under the ClawHub algorithm",
	}
	resolveUnsupported = Finding{
		RuleID:      RuleResolveUnsupported,
		Severity:    SeverityMedium,
		OWASP:       "ASK-02",
		Explanation: "the source kind cannot be resolved yet, so its integrity cannot be locked",
	}
	resolveFailed = Finding{
		RuleID:      RuleResolveFailed,
		Severity:    SeverityHigh,
		OWASP:       "ASK-02",
		Explanation: "the source could not be resolved to verifiable code",
	}
)
