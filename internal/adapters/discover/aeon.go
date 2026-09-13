package discover

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Aeon discovers skills published by an AEON agent repo. AEON keeps its skills
// at a top-level skills/<slug>/SKILL.md — not under .claude/skills like the
// per-tool adapters expect — so without this a scan of an AEON checkout sees
// almost nothing. Discovery is gated on AEON's aeon.yml marker so the adapter
// is inert for every other repo: a plain skills/ directory elsewhere must not
// get AEON artifacts injected into its scan.
type Aeon struct{}

// NewAeon constructs the AEON skills discoverer.
func NewAeon() *Aeon { return &Aeon{} }

// Tool returns the canonical tool id.
func (a *Aeon) Tool() string { return "aeon" }

// Discover satisfies ports.Discoverer. It only reports for project scopes whose
// root carries the aeon.yml marker.
func (a *Aeon) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(sc.Path, "aeon.yml")); err != nil {
			continue // not an AEON repo — stay inert
		}
		if _, err := os.Stat(filepath.Join(sc.Path, ManifestFile)); err == nil {
			continue // a declared layout owns this root
		}
		skills := skillsFromDir(a.Tool(), filepath.Join(sc.Path, "skills"), sc.String())
		for i := range skills {
			skills[i].Capabilities = capabilitiesFromSkill(skills[i].DiscoveredFrom)
		}
		out = append(out, skills...)
	}
	return out, nil
}

// callLine matches a line that actually performs network egress — AEON mandates
// ./secretcurl for auth'd APIs and curl/WebFetch for public ones. Hosts are
// harvested only from these lines, so a URL that merely appears in prose (a doc
// link) does not inflate the skill's declared reach and trip the
// capability-expansion gate on a benign edit.
var callLine = regexp.MustCompile(`(?i)\b(secretcurl|curl|wget|webfetch)\b`)

var urlHost = regexp.MustCompile(`https?://[^\s"'` + "`" + `)]+`)

// capabilitiesFromSkill fingerprints a skill's egress: the set of hosts it
// reaches from a network-call line. This is the security-relevant capability for
// a prose skill — a rug pull adds a new exfiltration endpoint — and it changes
// far less often than the skill's wording, so gating on its expansion stays
// low-noise where gating on raw content would not.
func capabilitiesFromSkill(skillMd string) artifact.Capabilities {
	f, err := os.Open(skillMd)
	if err != nil {
		return artifact.Capabilities{}
	}
	defer func() { _ = f.Close() }()

	hosts := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !callLine.MatchString(line) {
			continue
		}
		for _, raw := range urlHost.FindAllString(line, -1) {
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				hosts[u.Host] = true
			}
		}
	}
	return networkCapabilities(hosts)
}
