package dashboard

import (
	"strconv"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// DashArtifact is the artifact shape the dashboard UI consumes (mirrors the
// TypeScript Artifact in controlplane/web/lib/scan-data.ts). It is assembled
// from the live inventory joined with the locked lockfile, so the frontend
// stays a thin fetch-and-render.
type DashArtifact struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Kind        string        `json:"kind"`  // skill | mcp | plugin | <type>
	Agent       string        `json:"agent"` // display name of the tool
	Version     string        `json:"version"`
	Source      string        `json:"source"`
	InstalledAt string        `json:"installedAt"`
	Hash        string        `json:"hash"`
	LockedHash  string        `json:"lockedHash"`
	Drift       string        `json:"drift"` // verified | drifted | new | unsigned
	Findings    []DashFinding `json:"findings"`
}

// DashFinding mirrors the TS Finding.
type DashFinding struct {
	ID       string `json:"id"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	Location string `json:"location"`
}

// approvedSet returns the IDs of locked artifacts with a signed-and-approved
// approval — the inputs the "verified" vs "unsigned" distinction needs.
// (Signature validity is checked upstream; here we treat an approval bearing a
// signature as trusted. Slice 3 wires real keyring verification.)
func approvedSet(locked lockfile.Lockfile) map[string]bool {
	out := make(map[string]bool)
	for _, e := range locked.Artifacts {
		if e.Approval != nil && e.Approval.Status == "approved" && e.Approval.Sig != "" {
			out[e.ID] = true
		}
	}
	return out
}

// BuildScan assembles the dashboard view from the current inventory, the
// locked snapshot, and the set of approved-and-signed artifact IDs. It is
// pure: all IO (building inventory, reading the lockfile, verifying
// signatures) happens in the caller.
func BuildScan(current, locked lockfile.Lockfile, approved map[string]bool) []DashArtifact {
	diff := lockfile.Compare(locked, current)
	drift := driftByID(diff)
	lockedHash := map[string]string{}
	for _, e := range locked.Artifacts {
		lockedHash[e.ID] = e.ContentHash
	}
	scanStamp := relativeStamp(current.GeneratedAt)

	out := make([]DashArtifact, 0, len(current.Artifacts))
	for _, e := range current.Artifacts {
		out = append(out, DashArtifact{
			ID:          e.ID,
			Name:        e.Name,
			Kind:        kindOf(e.Type),
			Agent:       agentName(e.Tool),
			Version:     versionOf(e.Source),
			Source:      e.Source.Ref,
			InstalledAt: scanStamp, // fallback until per-artifact mtime is captured (Slice 4)
			Hash:        e.ContentHash,
			LockedHash:  lockedHash[e.ID],
			Drift:       driftStatus(e.ID, drift, lockedHash, approved),
			Findings:    mapFindings(e.Findings),
		})
	}
	return out
}

// driftByID indexes the changes that signal drift (content/version/integrity/
// cert) and additions, by artifact ID.
func driftByID(diff lockfile.Diff) map[string]lockfile.DriftKind {
	out := make(map[string]lockfile.DriftKind)
	for _, c := range diff.Changes {
		switch c.Kind {
		case lockfile.DriftAdded:
			out[c.ID] = lockfile.DriftAdded
		case lockfile.DriftContentChanged, lockfile.DriftVersionChanged,
			lockfile.DriftIntegrityChanged, lockfile.DriftCertRotated:
			// content change is the loudest signal; don't let a weaker kind overwrite it
			if out[c.ID] != lockfile.DriftContentChanged {
				out[c.ID] = c.Kind
			}
		}
	}
	return out
}

// driftStatus collapses our richer drift model into the dashboard's four
// mutually-exclusive states, in priority order: drifted > new > unsigned >
// verified.
func driftStatus(id string, drift map[string]lockfile.DriftKind, lockedHash map[string]string, approved map[string]bool) string {
	switch drift[id] {
	case lockfile.DriftContentChanged, lockfile.DriftVersionChanged,
		lockfile.DriftIntegrityChanged, lockfile.DriftCertRotated:
		return "drifted"
	case lockfile.DriftAdded:
		return "new"
	}
	if _, locked := lockedHash[id]; !locked {
		return "new" // not in the lockfile at all
	}
	if !approved[id] {
		return "unsigned"
	}
	return "verified"
}

// kindOf maps the artifact type onto the dashboard's coarse kind.
func kindOf(t artifact.Type) string {
	switch t {
	case artifact.TypeMCPServer:
		return "mcp"
	case artifact.TypeSkill:
		return "skill"
	case artifact.TypePlugin:
		return "plugin"
	default:
		return string(t) // subagent | hook | rules | context
	}
}

// agentName maps a tool id to its display name.
func agentName(tool string) string {
	switch tool {
	case "claude-code":
		return "Claude Code"
	case "cursor":
		return "Cursor"
	case "gemini":
		return "Gemini"
	case "opencode":
		return "OpenCode"
	case "codex":
		return "Codex"
	case "windsurf":
		return "Windsurf"
	case "copilot-cli":
		return "GitHub Copilot"
	default:
		return tool
	}
}

// versionOf derives a human version from the pinned source: npm uses the ref
// as a version, git a short commit, others have none.
func versionOf(s artifact.Source) string {
	switch s.Kind {
	case artifact.SourceNPM:
		return s.Ref
	case artifact.SourceGit:
		if len(s.Ref) > 12 {
			return s.Ref[:12]
		}
		return s.Ref
	default:
		return ""
	}
}

func mapFindings(fs []finding.Finding) []DashFinding {
	out := make([]DashFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, DashFinding{
			ID:       f.RuleID + "|" + f.File + "|" + strconv.Itoa(f.Line),
			Pattern:  patternOf(f.RuleID),
			Severity: severityOf(f.Severity),
			Title:    titleOf(f),
			Detail:   f.Explanation,
			Evidence: f.Snippet,
			Location: location(f),
		})
	}
	return out
}

func severityOf(s finding.Severity) string {
	if s == finding.SeverityInfo {
		return "low" // the dashboard scale has no "info"
	}
	return string(s)
}

func location(f finding.Finding) string {
	if f.File == "" {
		return ""
	}
	if f.Line > 0 {
		return f.File + ":" + strconv.Itoa(f.Line)
	}
	return f.File
}

func relativeStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04")
}
