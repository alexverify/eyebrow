// Package sbom renders a lockfile as a CycloneDX 1.6 SBOM: one component per
// discovered artifact (skill, MCP server, plugin, …) and one vulnerability per
// static-analysis finding. It is a pure mapping over the lockfile — everything
// it needs (pinned refs, content hashes, integrity, provenance, findings) is
// already recorded — so even a tiny team can hand an auditable supply-chain
// document to its first enterprise customer.
package sbom

import (
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// BOM is the subset of the CycloneDX 1.6 schema eyebrow emits.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`   // always "CycloneDX"
	SpecVersion     string          `json:"specVersion"` // "1.6"
	Version         int             `json:"version"`     // document revision (1)
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Timestamp string `json:"timestamp"` // RFC3339
	Tools     []Tool `json:"tools"`
}

type Tool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type Component struct {
	Type       string     `json:"type"` // application | library
	BOMRef     string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"` // "SHA-256"
	Content string `json:"content"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Source      Source   `json:"source"`
	Ratings     []Rating `json:"ratings,omitempty"`
	Description string   `json:"description,omitempty"`
	Affects     []Affect `json:"affects,omitempty"`
}

type Source struct {
	Name string `json:"name"`
}

type Rating struct {
	Severity string `json:"severity"` // critical|high|medium|low|info
	Method   string `json:"method,omitempty"`
}

type Affect struct {
	Ref string `json:"ref"`
}

// Build maps a lockfile to a CycloneDX BOM. ts stamps the metadata (pass an RFC3339 string).
func Build(lf lockfile.Lockfile, ts string) BOM {
	components := make([]Component, 0, len(lf.Artifacts))
	var vulns []Vulnerability
	for _, e := range lf.Artifacts {
		components = append(components, component(e))
		for _, f := range e.Findings {
			vulns = append(vulns, vulnerability(e.ID, f))
		}
	}
	return BOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		Version:         1,
		Metadata:        Metadata{Timestamp: ts, Tools: []Tool{{Vendor: "eyebrow", Name: "eyebrow"}}},
		Components:      components,
		Vulnerabilities: vulns,
	}
}

func component(e lockfile.Entry) Component {
	c := Component{
		Type:    componentType(e.Type),
		BOMRef:  e.ID,
		Name:    e.Name,
		Version: version(e.Source),
		PURL:    purl(e.Source),
	}
	if h := sha256Hex(e.ContentHash); h != "" {
		c.Hashes = []Hash{{Alg: "SHA-256", Content: h}}
	}
	c.Properties = properties(e)
	return c
}

func properties(e lockfile.Entry) []Property {
	add := func(props []Property, name, val string) []Property {
		if val == "" {
			return props
		}
		return append(props, Property{Name: name, Value: val})
	}
	var p []Property
	p = add(p, "eyebrow:tool", e.Tool)
	p = add(p, "eyebrow:type", string(e.Type))
	p = add(p, "eyebrow:scope", e.Scope)
	p = add(p, "eyebrow:sourceKind", string(e.Source.Kind))
	p = add(p, "eyebrow:integrity", e.Source.Integrity)
	p = add(p, "eyebrow:provenance", e.Source.Provenance)
	if e.Quarantined {
		p = add(p, "eyebrow:quarantined", "true")
	}
	if e.Frozen {
		p = add(p, "eyebrow:frozen", "true")
	}
	if e.Approval != nil && e.Approval.Status == "approved" {
		p = add(p, "eyebrow:approved", "true")
	}
	return p
}

func vulnerability(ref string, f finding.Finding) Vulnerability {
	return Vulnerability{
		ID:          f.RuleID,
		Source:      Source{Name: "eyebrow"},
		Ratings:     []Rating{{Severity: string(f.Severity), Method: "other"}},
		Description: f.Explanation,
		Affects:     []Affect{{Ref: ref}},
	}
}

// componentType maps an artifact type onto a CycloneDX component type. Things
// that execute (MCP servers, plugins, hooks) are applications; the rest are
// libraries.
func componentType(t artifact.Type) string {
	switch t {
	case artifact.TypeMCPServer, artifact.TypePlugin, artifact.TypeHook:
		return "application"
	default:
		return "library"
	}
}

// version derives a component version from the pinned source ref.
func version(s artifact.Source) string {
	if s.Kind == artifact.SourceNPM {
		if _, ver := splitNameVersion(s.Ref); ver != "" {
			return ver
		}
	}
	if s.Kind == artifact.SourceGit && len(s.Ref) > 12 {
		return s.Ref[:12]
	}
	return ""
}

// purl emits a Package URL for npm sources; other kinds have no standard purl.
func purl(s artifact.Source) string {
	if s.Kind != artifact.SourceNPM {
		return ""
	}
	name, ver := splitNameVersion(s.Ref)
	if name == "" {
		return ""
	}
	if ver == "" {
		return "pkg:npm/" + name
	}
	return "pkg:npm/" + name + "@" + ver
}

// splitNameVersion splits an npm ref "name@version" (or "@scope/name@version")
// at the last '@', so a leading scope '@' is not mistaken for the separator.
func splitNameVersion(ref string) (name, version string) {
	if i := strings.LastIndex(ref, "@"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// sha256Hex returns the hex digest from a "sha256-<hex>" content hash, or "" if
// the value is empty or not in that form.
func sha256Hex(contentHash string) string {
	if strings.HasPrefix(contentHash, digest.Prefix) {
		return strings.TrimPrefix(contentHash, digest.Prefix)
	}
	return ""
}
