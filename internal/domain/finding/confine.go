package finding

// RuleLocalOutsideRoot is the rule id for a local source that a confined scan
// refused to read because its path resolves outside the scan root.
const RuleLocalOutsideRoot = "LOCAL-OUTSIDE-ROOT"

// LocalOutsideRoot is the finding a confined scan records in place of hashing
// or analyzing a local source outside the scan root. It carries no path or
// content, so nothing about the refused location reaches the report.
func LocalOutsideRoot() Finding {
	return Finding{
		RuleID:      RuleLocalOutsideRoot,
		Severity:    SeverityHigh,
		OWASP:       "ASK-02",
		Explanation: "local source is outside the scanned tree or missing from it, and was not read",
	}
}
