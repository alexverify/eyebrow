package dashboard

import (
	"sort"
	"strconv"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
	"github.com/alexverify/agentguard/internal/domain/provenance"
	"github.com/alexverify/agentguard/internal/domain/trust"
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

	// Detail-view fields (the per-artifact security profile).
	Scope          string           `json:"scope"`
	SourceKind     string           `json:"sourceKind"`
	DiscoveredFrom string           `json:"discoveredFrom"`
	Command        string           `json:"command,omitempty"` // MCP launch command
	Args           []string         `json:"args,omitempty"`
	EnvKeys        []string         `json:"envKeys,omitempty"` // env var names only — values are never exposed
	Integrity      string           `json:"integrity,omitempty"`
	CertSPKI       string           `json:"certSpki,omitempty"`
	Capabilities   DashCapabilities `json:"capabilities"`
	Files          []DashFile       `json:"files"`
	Approval       *DashApproval    `json:"approval,omitempty"`

	// Trust verdict (A1) and drift interpretation (A3).
	Trust        int          `json:"trust"`
	Verdict      string       `json:"verdict"` // trusted | review | quarantine
	TrustReasons []DashReason `json:"trustReasons"`
	DriftClass   string       `json:"driftClass"`  // none|updated|mutated|broken|added|removed
	DriftDetail  string       `json:"driftDetail"` // human one-liner for the change card

	// Remediation state (C2) and provenance grade (B1).
	Quarantined bool              `json:"quarantined,omitempty"`
	Frozen      bool              `json:"frozen,omitempty"`
	Provenance  provenance.Ladder `json:"provenance"`
}

// DashReason is one additive contribution to the trust score, for the breakdown.
type DashReason struct {
	Label string `json:"label"`
	Delta int    `json:"delta"`
}

// DashCapabilities mirrors the declared powers of an artifact, plus the diff
// against the locked snapshot (A2) so the UI can show capability expansion.
type DashCapabilities struct {
	Exec       bool     `json:"exec"`
	Network    []string `json:"network"`
	Filesystem []string `json:"filesystem"`

	ExecNewlyAdded    bool     `json:"execNewlyAdded,omitempty"`
	AddedNetwork      []string `json:"addedNetwork,omitempty"`
	RemovedNetwork    []string `json:"removedNetwork,omitempty"`
	AddedFilesystem   []string `json:"addedFilesystem,omitempty"`
	RemovedFilesystem []string `json:"removedFilesystem,omitempty"`
	SensitiveAdded    []string `json:"sensitiveAdded,omitempty"` // added FS paths that touch secrets
}

// DashFile is one entry in the artifact's file manifest.
type DashFile struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// DashApproval is the approval/sign-off state shown in the detail view.
type DashApproval struct {
	Status string `json:"status"`
	By     string `json:"by,omitempty"`
	At     string `json:"at,omitempty"`
	Signed bool   `json:"signed"`
}

// DashFinding mirrors the TS Finding.
type DashFinding struct {
	ID       string `json:"id"`
	RuleID   string `json:"ruleId"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	OWASP    string `json:"owasp,omitempty"`
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
	classes := lockfile.Classify(locked, current)
	lockedByID := map[string]lockfile.Entry{}
	for _, e := range locked.Artifacts {
		lockedByID[e.ID] = e
	}
	scanStamp := relativeStamp(current.GeneratedAt)

	out := make([]DashArtifact, 0, len(current.Artifacts))
	for _, e := range current.Artifacts {
		prev, hasLocked := lockedByID[e.ID]
		class := classes[e.ID]

		capDiff := lockfile.DiffCapabilities(prev.Capabilities, e.Capabilities)
		secretFS := trust.SensitivePaths(e.Capabilities.Filesystem)

		score := trust.Evaluate(trust.Input{
			Findings:         e.Findings,
			Drift:            class,
			Source:           e.Source,
			Signed:           approved[e.ID],
			Exec:             e.Capabilities.Exec,
			Network:          len(e.Capabilities.Network) > 0,
			SecretFilesystem: len(secretFS) > 0,
		})

		// A quarantined artifact is, by definition, not trusted — override the
		// verdict regardless of its numeric score.
		verdict := string(score.Verdict)
		if prev.Quarantined {
			verdict = string(trust.Quarantine)
		}

		out = append(out, DashArtifact{
			ID:             e.ID,
			Name:           e.Name,
			Kind:           kindOf(e.Type),
			Agent:          agentName(e.Tool),
			Version:        versionOf(e.Source),
			Source:         e.Source.Ref,
			InstalledAt:    installedAt(e.ModifiedAt, scanStamp),
			Hash:           e.ContentHash,
			LockedHash:     prev.ContentHash,
			Drift:          driftStatus(class, hasLocked, approved[e.ID]),
			Findings:       mapFindings(e.Findings),
			Scope:          e.Scope,
			SourceKind:     string(e.Source.Kind),
			DiscoveredFrom: e.DiscoveredFrom,
			Command:        e.Source.Command,
			Args:           e.Source.Args,
			EnvKeys:        envKeys(e.Source.Env),
			Integrity:      e.Source.Integrity,
			CertSPKI:       e.Source.CertSPKI,
			Capabilities: DashCapabilities{
				Exec:              e.Capabilities.Exec,
				Network:           e.Capabilities.Network,
				Filesystem:        e.Capabilities.Filesystem,
				ExecNewlyAdded:    capDiff.ExecAdded,
				AddedNetwork:      capDiff.NetworkAdded,
				RemovedNetwork:    capDiff.NetworkRemoved,
				AddedFilesystem:   capDiff.FilesystemAdded,
				RemovedFilesystem: capDiff.FilesystemRemoved,
				SensitiveAdded:    trust.SensitivePaths(capDiff.FilesystemAdded),
			},
			Files:        mapFiles(e.Files),
			Approval:     mapApproval(prev.Approval),
			Trust:        score.Value,
			Verdict:      verdict,
			TrustReasons: mapReasons(score.Reasons),
			DriftClass:   string(class),
			DriftDetail:  driftDetail(class, prev, e),
			Quarantined:  prev.Quarantined,
			Frozen:       prev.Frozen,
			Provenance:   provenance.Assess(e.Source, approved[e.ID]),
		})
	}
	return out
}

// mapReasons converts the domain reasons into the DTO shape.
func mapReasons(rs []trust.Reason) []DashReason {
	out := make([]DashReason, 0, len(rs))
	for _, r := range rs {
		out = append(out, DashReason{Label: r.Label, Delta: r.Delta})
	}
	return out
}

// driftDetail is the human one-liner shown on the change card.
func driftDetail(class lockfile.DriftClass, prev, cur lockfile.Entry) string {
	switch class {
	case lockfile.DriftClassMutated:
		return "content hash changed with no version bump — what runs now is not what you locked"
	case lockfile.DriftClassBroken:
		return "updated, but the new version's integrity could not be verified"
	case lockfile.DriftClassUpdated:
		if prev.Source.Ref != "" && cur.Source.Ref != "" && prev.Source.Ref != cur.Source.Ref {
			return "updated from " + prev.Source.Ref + " to " + cur.Source.Ref
		}
		return "updated since last audit"
	case lockfile.DriftClassAdded:
		return "newly discovered — not in the lockfile"
	default:
		return ""
	}
}

// installedAt prefers the captured file mtime, falling back to the scan
// timestamp when no mtime is known (e.g. inline/remote artifacts).
func installedAt(mod time.Time, scanStamp string) string {
	if !mod.IsZero() {
		return mod.UTC().Format("2006-01-02 15:04")
	}
	return scanStamp
}

// envKeys returns only the env var names, sorted — values may be secrets and
// are never exposed to the dashboard.
func envKeys(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mapFiles(files []artifact.FileRef) []DashFile {
	out := make([]DashFile, 0, len(files))
	for _, f := range files {
		out = append(out, DashFile{Path: f.Path, Hash: f.Hash})
	}
	return out
}

func mapApproval(a *lockfile.Approval) *DashApproval {
	if a == nil {
		return nil
	}
	d := &DashApproval{Status: a.Status, By: a.By, Signed: a.Sig != ""}
	if !a.At.IsZero() {
		d.At = a.At.UTC().Format("2006-01-02 15:04")
	}
	return d
}

// driftStatus collapses the DriftClass into the dashboard's mutually-exclusive
// states, in priority order: drifted > updated > new > unsigned > verified.
func driftStatus(class lockfile.DriftClass, hasLocked, approved bool) string {
	switch class {
	case lockfile.DriftClassMutated, lockfile.DriftClassBroken:
		return "drifted"
	case lockfile.DriftClassUpdated:
		return "updated"
	case lockfile.DriftClassAdded:
		return "new"
	}
	if !hasLocked {
		return "new"
	}
	if !approved {
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
			RuleID:   f.RuleID,
			Pattern:  patternOf(f.RuleID),
			Severity: severityOf(f.Severity),
			OWASP:    f.OWASP,
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
