package resolve

import (
	"strings"
	"testing"
)

func TestParseNPMSpec(t *testing.T) {
	cases := []struct {
		ref           string
		name, version string
		pinned        bool
	}{
		{"some-mcp@1.4.2", "some-mcp", "1.4.2", true},
		{"some-mcp@latest", "some-mcp", "latest", false},
		{"some-mcp", "some-mcp", "", false},
		{"some-mcp@^1.2.0", "some-mcp", "^1.2.0", false},
		{"@scope/name@2.0.0", "@scope/name", "2.0.0", true},
		{"@scope/name", "@scope/name", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, version, pinned := parseNPMSpec(c.ref)
		if name != c.name || version != c.version || pinned != c.pinned {
			t.Errorf("parseNPMSpec(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.ref, name, version, pinned, c.name, c.version, c.pinned)
		}
	}
}

func TestIsRegistrySpec(t *testing.T) {
	cases := []struct {
		ref    string
		accept bool
	}{
		{"left-pad", true},
		{"left-pad@1.3.0", true},
		{"@scope/name", true},
		{"@scope/name@^2.0.0", true},
		{"name@latest", true},
		{"name@>=1 <2", false}, // whitespace in version
		{"github:attacker/pwn", false},
		{"git+https://x/y.git", false},
		{"https://x/y.tgz", false},
		{"file:../etc", false},
		{"npm:other@1", false},
		{"../x", false},
		{"-flag", false},
		{"@/x", false},
		{strings.Repeat("a", 215), false},
		{"", false},
	}
	for _, c := range cases {
		if got := isRegistrySpec(c.ref); got != c.accept {
			t.Errorf("isRegistrySpec(%q) = %v, want %v", c.ref, got, c.accept)
		}
	}
}

func TestParseNPMStringOutput(t *testing.T) {
	if got := parseNPMStringOutput([]byte(`"1.4.2"`)); got != "1.4.2" {
		t.Errorf("string form = %q", got)
	}
	if got := parseNPMStringOutput([]byte(`["1.4.1","1.4.2"]`)); got != "1.4.2" {
		t.Errorf("array form = %q", got)
	}
	if got := parseNPMStringOutput([]byte("  \"sha512-abc\" \n")); got != "sha512-abc" {
		t.Errorf("whitespace form = %q", got)
	}
}
