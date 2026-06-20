package sbom

import (
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

func hasProp(c Component, name, val string) bool {
	for _, p := range c.Properties {
		if p.Name == name && p.Value == val {
			return true
		}
	}
	return false
}

func TestBuildMapsComponentsAndVulns(t *testing.T) {
	a := artifact.Artifact{
		ID: "id1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "pg-mcp",
		ContentHash: "sha256-deadbeef",
		Source: artifact.Source{
			Kind: artifact.SourceNPM, Ref: "pg-mcp@1.2.3",
			Integrity: "sha512-x", Provenance: "https://slsa.dev/provenance/v1",
		},
		Findings: []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical, Explanation: "bad"}},
	}
	lf := lockfile.Build([]artifact.Artifact{a}, time.Unix(0, 0).UTC(), "t")
	bom := Build(lf, "2026-06-14T00:00:00Z")

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Fatalf("bom header = %+v", bom.Metadata)
	}
	if len(bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(bom.Components))
	}
	c := bom.Components[0]
	if c.Type != "application" {
		t.Errorf("mcp_server → application, got %q", c.Type)
	}
	if c.PURL != "pkg:npm/pg-mcp@1.2.3" {
		t.Errorf("purl = %q", c.PURL)
	}
	if c.Version != "1.2.3" {
		t.Errorf("version = %q", c.Version)
	}
	if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || c.Hashes[0].Content != "deadbeef" {
		t.Errorf("hashes = %+v", c.Hashes)
	}
	if !hasProp(c, "eyebrow:provenance", "https://slsa.dev/provenance/v1") {
		t.Errorf("provenance property missing: %+v", c.Properties)
	}

	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %d", len(bom.Vulnerabilities))
	}
	v := bom.Vulnerabilities[0]
	if v.ID != "RCE" || len(v.Affects) != 1 || v.Affects[0].Ref != "id1" {
		t.Errorf("vuln = %+v", v)
	}
	if len(v.Ratings) != 1 || v.Ratings[0].Severity != "critical" {
		t.Errorf("rating = %+v", v.Ratings)
	}
}

func TestSplitScopedName(t *testing.T) {
	name, ver := splitNameVersion("@scope/pkg@2.0.0")
	if name != "@scope/pkg" || ver != "2.0.0" {
		t.Fatalf("scoped split: %q %q", name, ver)
	}
}

func TestSha256HexStripsPrefixOnly(t *testing.T) {
	if got := sha256Hex("sha256-abc123"); got != "abc123" {
		t.Errorf("prefixed → hex, got %q", got)
	}
	if got := sha256Hex(""); got != "" {
		t.Errorf("empty → empty, got %q", got)
	}
}
