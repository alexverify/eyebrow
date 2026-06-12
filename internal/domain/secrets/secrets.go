// Package secrets detects and redacts well-known credential shapes in byte
// streams. Pure domain: the egress proxy uses it on plain-HTTP request bodies
// before forwarding, and the audit trail records only counts and kinds —
// never the matched values.
//
// The shapes are deliberately high-precision (distinct prefixes, fixed
// alphabets, length bounds): a redactor that mangles ordinary payloads gets
// the proxy turned off, which protects nobody.
package secrets

import "regexp"

// Match locates one detected secret. The value itself is never stored.
type Match struct {
	Kind  string
	Start int
	End   int
}

// shape is one detectable credential pattern.
type shape struct {
	kind string
	re   *regexp.Regexp
}

var shapes = []shape{
	{"aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{10,}`)},
	{"openai-key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{"github-token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[bporas]-[A-Za-z0-9-]{10,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"private-key-pem", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	// 64-byte payloads in base58 (Solana keypairs/seeds) encode to 85–90 chars.
	{"base58-seed", regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{85,90}\b`)},
}

// Scan returns every credential-shaped substring, ordered by position.
// Overlapping detections keep the earliest (then longest) match.
func Scan(b []byte) []Match {
	var all []Match
	for _, s := range shapes {
		for _, loc := range s.re.FindAllIndex(b, -1) {
			all = append(all, Match{Kind: s.kind, Start: loc[0], End: loc[1]})
		}
	}
	return dedupeOverlaps(all)
}

// Redact replaces every match with "[REDACTED:<kind>]" and reports what was
// found. A clean input is returned as-is.
func Redact(b []byte) ([]byte, []Match) {
	ms := Scan(b)
	if len(ms) == 0 {
		return b, nil
	}
	out := make([]byte, 0, len(b))
	prev := 0
	for _, m := range ms {
		out = append(out, b[prev:m.Start]...)
		out = append(out, []byte("[REDACTED:"+m.Kind+"]")...)
		prev = m.End
	}
	out = append(out, b[prev:]...)
	return out, ms
}

// dedupeOverlaps sorts by position and drops matches overlapping an earlier
// one (e.g. a JWT inside a larger token match).
func dedupeOverlaps(ms []Match) []Match {
	if len(ms) < 2 {
		return ms
	}
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if ms[j].Start < ms[i].Start || (ms[j].Start == ms[i].Start && ms[j].End > ms[i].End) {
				ms[i], ms[j] = ms[j], ms[i]
			}
		}
	}
	out := ms[:1]
	for _, m := range ms[1:] {
		if m.Start >= out[len(out)-1].End {
			out = append(out, m)
		}
	}
	return out
}
