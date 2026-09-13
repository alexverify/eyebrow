package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// SkillsLock discovers skills published by repos in the skills-lock ecosystem
// (dexter-mcp, solana-foundation/pay). Those repos keep their catalog at a
// top-level skills/<slug>/SKILL.md and declare it with a skills-lock.json at
// the root — a provenance lock that records where a skill came from but does
// not fingerprint its content or reach. Discovery is gated on that marker so
// the adapter is inert for every other repo: a plain skills/ directory
// elsewhere must not get artifacts injected into its scan. AEON repos use the
// same layout under their own aeon.yml marker; when both markers are present
// the AEON adapter owns the layout and this one stays inert, so no skill is
// reported twice.
type SkillsLock struct{}

// NewSkillsLock constructs the skills-lock catalog discoverer.
func NewSkillsLock() *SkillsLock { return &SkillsLock{} }

// Tool returns the canonical tool id.
func (s *SkillsLock) Tool() string { return "skills-lock" }

// Discover satisfies ports.Discoverer. It only reports for project scopes
// whose root carries the skills-lock.json marker (and no aeon.yml).
func (s *SkillsLock) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(sc.Path, "skills-lock.json")); err != nil {
			continue // not a skills-lock repo — stay inert
		}
		if _, err := os.Stat(filepath.Join(sc.Path, ManifestFile)); err == nil {
			continue // a declared layout owns this root
		}
		if _, err := os.Stat(filepath.Join(sc.Path, "aeon.yml")); err == nil {
			continue // AEON adapter owns this layout — avoid double-reporting
		}
		skills := skillsFromDir(s.Tool(), filepath.Join(sc.Path, "skills"), sc.String())
		for i := range skills {
			skills[i].Capabilities = capabilitiesFromSkill(skills[i].DiscoveredFrom)
		}
		out = append(out, skills...)
	}
	return out, nil
}
