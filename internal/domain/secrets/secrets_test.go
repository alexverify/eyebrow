package secrets

import (
	"strings"
	"testing"
)

func kinds(ms []Match) map[string]int {
	out := map[string]int{}
	for _, m := range ms {
		out[m.Kind]++
	}
	return out
}

func TestScanDetectsKnownShapes(t *testing.T) {
	cases := map[string]string{
		"aws-access-key":  "creds AKIAIOSFODNN7EXAMPLE here",
		"anthropic-key":   "key sk-ant-api03-x7Jf9q2LpQ8wYzAbCdEf in body",
		"openai-key":      "Authorization: Bearer sk-proj4bCdEfGhIjKlMnOpQrStUv",
		"github-token":    "token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"slack-token":     "hook xoxb-123456789012-abcdefghijklm",
		"google-api-key":  "AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v",
		"jwt":             "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
		"private-key-pem": "-----BEGIN RSA PRIVATE KEY-----",
		"base58-seed":     "seed 4mZK9V2RrLBGTLNqvkuVxLkM4dYJSGhDpQbTWKjMv4PypNvg7smC1JqxzNyU8bqo1pcv5DcW9vPpaZkkVKEuyUVB ok",
	}
	for kind, text := range cases {
		ms := Scan([]byte(text))
		if kinds(ms)[kind] == 0 {
			t.Errorf("Scan did not detect %s in %q (got %v)", kind, text, ms)
		}
	}
}

func TestScanCleanTextHasNoFalsePositives(t *testing.T) {
	clean := []byte(`{"query": "SELECT * FROM users WHERE id = 42", "limit": 100,
		"note": "deploy skipped, see ticket ABC-123", "url": "https://api.github.com/repos"}`)
	if ms := Scan(clean); len(ms) != 0 {
		t.Errorf("false positives on benign payload: %v", ms)
	}
}

func TestRedactReplacesAllMatches(t *testing.T) {
	body := []byte(`{"aws": "AKIAIOSFODNN7EXAMPLE", "gh": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}`)
	out, ms := Redact(body)
	if len(ms) != 2 {
		t.Fatalf("got %d matches, want 2: %v", len(ms), ms)
	}
	s := string(out)
	if strings.Contains(s, "AKIA") || strings.Contains(s, "ghp_") {
		t.Errorf("secrets survived redaction: %s", s)
	}
	if !strings.Contains(s, "[REDACTED:aws-access-key]") || !strings.Contains(s, "[REDACTED:github-token]") {
		t.Errorf("redaction markers missing: %s", s)
	}
	// Non-secret structure must survive.
	if !strings.Contains(s, `{"aws": "`) {
		t.Errorf("surrounding content damaged: %s", s)
	}
}

func TestRedactNoMatchesReturnsInputUntouched(t *testing.T) {
	in := []byte("nothing to see")
	out, ms := Redact(in)
	if len(ms) != 0 || string(out) != "nothing to see" {
		t.Fatalf("clean input must pass through, got %q %v", out, ms)
	}
}
