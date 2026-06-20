package dashboard

import (
	"sort"
	"strconv"
	"time"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/provenance"
	"github.com/alexverify/assay/internal/domain/reach"
	"github.com/alexverify/assay/internal/domain/reputation"
	"github.com/alexverify/assay/internal/domain/risk"
	"github.com/alexverify/assay/internal/domain/textdiff"
	"github.com/alexverify/assay/internal/domain/timeline"
	"github.com/alexverify/assay/internal/domain/trust"
	"github.com/alexverify/assay/internal/domain/usage"
)

// DashArtifact is the artifact shape the dashboard UI consumes (mirrors the
// TypeScript Artifact in controlplane/web/lib/scan-data.ts). It is assembled
// from the live inventory joined with the locked lockfile, so the frontend
// stays a thin fetch-and-render.
type DashArtifact struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"` // stated purpose, from frontmatter
	Kind        string        `json:"kind"`                  // skill | mcp | plugin | <type>
	Agent       string        `json:"agent"`                 // display name of the tool
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

	// Shadow flags an unaccounted artifact (B3): newly present but not in the
	// lockfile and not pulled from a known registry/package source — an
	// "installed but never declared" extension (OWASP MCP09 / AST09).
	Shadow bool `json:"shadow,omitempty"`

	// FileChanges is the file-manifest diff against the locked snapshot (H1):
	// which files were added, removed, or modified in a drift. Populated only
	// when a locked prior exists and its manifest differs — the content-free,
	// offline core of the rug-pull diff view. nil when there is nothing to diff.
	FileChanges *lockfile.FileDiff `json:"fileChanges,omitempty"`

	// LineDiffs is the literal line-level change per file (H1b): the added/removed
	// lines of a drift, when the approved and current bytes are both in the local
	// blob store. Empty when the store has no baseline (degrades to FileChanges).
	LineDiffs []DashLineDiff `json:"lineDiffs,omitempty"`

	// Usage is the runtime invocation summary (F1): when this artifact last ran,
	// when it first ran, and how many times. Sourced from the MCP shim's audit
	// log, joined by server name; nil for artifacts with no telemetry path yet
	// (skills/plugins/hooks have no runtime hook surface — an honest gap).
	Usage *DashUsage `json:"usage,omitempty"`

	// Sleeper flags the dormant-then-active triple (F2): an old install that lay
	// unused, drifted, then fired for the first time. nil unless the rule trips.
	Sleeper *DashSleeper `json:"sleeper,omitempty"`

	// Timeline is the per-artifact event ribbon (F4): installed → approved →
	// invoked → drifted, ordered in time. Empty when no dated milestone is known.
	Timeline []timeline.Event `json:"timeline,omitempty"`

	// Reputation is the opt-in community trust signal for this exact content
	// hash (H3): how many other users trust it and when it was first seen. nil
	// when the corpus is absent or has no entry (unknown, never a negative claim).
	Reputation *DashReputation `json:"reputation,omitempty"`
}

// DashLineDiff is the line-level change in one file of a drift (H1b): the actual
// `+`/`-` lines an auditor reads to confirm a rug pull, grouped into hunks.
type DashLineDiff struct {
	Path    string          `json:"path"`
	Status  string          `json:"status"` // modified | added | removed
	Added   int             `json:"added"`
	Removed int             `json:"removed"`
	Hunks   []textdiff.Hunk `json:"hunks"`
}

// DashReputation is the per-artifact community trust signal (H3).
type DashReputation struct {
	Trusters  int    `json:"trusters"`
	FirstSeen string `json:"firstSeen,omitempty"`
	Grade     string `json:"grade"` // unknown | emerging | established
}

// DashUsage is the per-artifact runtime invocation summary (F1).
type DashUsage struct {
	FirstUsed   string `json:"firstUsed,omitempty"`
	LastUsed    string `json:"lastUsed,omitempty"`
	LastUsedRel string `json:"lastUsedRel,omitempty"` // "3d ago" — relative to the scan
	Count       int    `json:"count"`
}

// DashSleeper carries the dormant-then-active finding for the drawer banner (F2).
type DashSleeper struct {
	DormantDays int    `json:"dormantDays"`
	Detail      string `json:"detail"`
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
	// File and Line are the structured anchor (File is POSIX-relative to the
	// artifact root) the code-view modal uses to fetch and scroll the source.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	// Safe marks a finding flagged as an accepted false positive: it stays shown
	// (severity and all) but is badged "flagged safe" and passes the CI gate.
	// SafeBy/SafeAt record the sign-off; SafeStale is true when the content
	// changed since it was flagged (the flag persists but is worth re-checking).
	Safe      bool   `json:"safe,omitempty"`
	SafeBy    string `json:"safeBy,omitempty"`
	SafeAt    string `json:"safeAt,omitempty"`
	SafeStale bool   `json:"safeStale,omitempty"`
	// Key is the finding's stable identity (rule|file|line), sent back to the
	// flag-safe endpoint.
	Key string `json:"key,omitempty"`

	// Capability × usage fusion (F3): how exercised the carrying artifact is
	// (live | exercised | unknown), and the fused urgency rank that lifts a
	// finding on code that actually runs above the same finding on dormant code.
	Liveness string `json:"liveness,omitempty"`
	RiskRank int    `json:"riskRank,omitempty"`

	// Reachability (H2): "reachable" for a runtime file, "inert" for a finding in
	// a test/example/vendored path that is almost certainly noise. A location
	// heuristic, not a call graph — it demotes, never deletes.
	Reach string `json:"reach,omitempty"`
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
func BuildScan(current, locked lockfile.Lockfile, approved map[string]bool, used map[string]usage.Stat, rep reputation.Source) []DashArtifact {
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
		dashUsage, sleeper := usageOf(e, class, used, current.GeneratedAt)
		ribbon := timelineOf(e, prev, class, used, current.GeneratedAt)
		live := livenessOf(e, used, current.GeneratedAt)

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
			Description:    e.Description,
			Kind:           kindOf(e.Type),
			Agent:          agentName(e.Tool),
			Version:        versionOf(e.Source),
			Source:         e.Source.Ref,
			InstalledAt:    installedAt(e.ModifiedAt, scanStamp),
			Hash:           e.ContentHash,
			LockedHash:     prev.ContentHash,
			Drift:          driftStatus(class, hasLocked, approved[e.ID]),
			Findings:       mapFindings(e.Findings, live, prev, e.ContentHash),
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
				Network:           orEmpty(e.Capabilities.Network),
				Filesystem:        orEmpty(e.Capabilities.Filesystem),
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
			Shadow:       isShadow(class, hasLocked, e.Source.Kind),
			FileChanges:  fileChanges(hasLocked, prev.Files, e.Files),
			Usage:        dashUsage,
			Sleeper:      sleeper,
			Timeline:     ribbon,
			Reputation:   reputationOf(e.ContentHash, rep),
		})
	}
	return out
}

// fileChanges returns the file-manifest diff against the locked snapshot (H1),
// or nil when there is nothing to diff: a brand-new artifact has no prior, and
// an unchanged manifest has no diff to show. Keeping it nil lets the UI render
// the section only when files actually moved.
func fileChanges(hasLocked bool, prev, cur []artifact.FileRef) *lockfile.FileDiff {
	if !hasLocked {
		return nil
	}
	d := lockfile.DiffFiles(prev, cur)
	if !d.Changed() {
		return nil
	}
	return &d
}

// AttachLineDiffs enriches the dashboard view with the line-level drift diff
// (H1b) for any artifact whose drift changed files, when the approved (locked)
// and current bytes are both available in the blob store. get returns a content
// hash's files (path → bytes), or nil when that hash was never captured. Any
// missing side degrades silently to the file-name list already in FileChanges —
// the line diff is an enhancement, never a requirement. Pure given get; the IO
// lives behind it.
func AttachLineDiffs(arts []DashArtifact, get func(contentHash string) (map[string][]byte, error)) {
	if get == nil {
		return
	}
	for i := range arts {
		a := &arts[i]
		if a.FileChanges == nil || a.LockedHash == "" || a.Hash == "" || a.LockedHash == a.Hash {
			continue
		}
		oldFiles, err := get(a.LockedHash)
		if err != nil || oldFiles == nil {
			continue
		}
		newFiles, err := get(a.Hash)
		if err != nil || newFiles == nil {
			continue
		}
		a.LineDiffs = lineDiffs(a.FileChanges, oldFiles, newFiles)
	}
}

// lineDiffs builds the per-file line diff for a drift from the captured bytes.
// A file missing from the store on a needed side (binary, oversized, or never
// captured) is skipped, leaving it to the file-name list. Hunks carry 3 lines
// of context around each change.
func lineDiffs(fc *lockfile.FileDiff, oldFiles, newFiles map[string][]byte) []DashLineDiff {
	var out []DashLineDiff
	add := func(path, status string, oldB, newB []byte) {
		lines := textdiff.Lines(string(oldB), string(newB))
		hunks := textdiff.Hunks(lines, 3)
		if len(hunks) == 0 {
			return
		}
		st := textdiff.Count(lines)
		out = append(out, DashLineDiff{Path: path, Status: status, Added: st.Added, Removed: st.Removed, Hunks: hunks})
	}
	for _, p := range fc.Modified {
		o, okO := oldFiles[p]
		n, okN := newFiles[p]
		if !okO || !okN {
			continue // need both sides to show a content diff
		}
		add(p, "modified", o, n)
	}
	for _, p := range fc.Added {
		if n, ok := newFiles[p]; ok {
			add(p, "added", nil, n)
		}
	}
	for _, p := range fc.Removed {
		if o, ok := oldFiles[p]; ok {
			add(p, "removed", o, nil)
		}
	}
	return out
}

// usageOf joins runtime invocation telemetry to an artifact (F1) and runs the
// dormant-then-active rule (F2). Telemetry is keyed by artifact name: MCP
// servers join on the shim's tool-call events, and skills/subagents/etc. join
// on the hook-fed activation events (F1b). An artifact with no matching event
// returns nil usage — the honest "no usage signal," surfaced in the UI rather
// than faked. The sleeper signal needs the install time (mtime) and the drift
// class, both already on the entry.
func usageOf(e lockfile.Entry, class lockfile.DriftClass, used map[string]usage.Stat, now time.Time) (*DashUsage, *DashSleeper) {
	stat, ok := statFor(used, e)
	if !ok {
		return nil, nil
	}
	du := &DashUsage{
		FirstUsed:   relativeStamp(stat.FirstUsed),
		LastUsed:    relativeStamp(stat.LastUsed),
		LastUsedRel: relativeAgo(stat.LastUsed, now),
		Count:       stat.Count,
	}
	sig := usage.Assess(usage.Input{
		InstalledAt: e.ModifiedAt,
		FirstUsed:   stat.FirstUsed,
		Drifted:     class == lockfile.DriftClassMutated || class == lockfile.DriftClassBroken,
		Now:         now,
	})
	if !sig.Sleeper {
		return du, nil
	}
	return du, &DashSleeper{DormantDays: sig.DormantDays, Detail: sig.Detail}
}

// timelineOf assembles the per-artifact event ribbon (F4) from the dated facts
// already on hand: the install mtime, the approval timestamp, the drift class
// (detected at scan time), and first/last invocation from the audit log. The
// domain Build orders and labels them; this seam only maps the available facts
// in. Usage events join by artifact name (tool calls for MCP servers,
// activations for skills/subagents — F1b); an artifact with no events simply
// contributes no use milestones.
func timelineOf(e, prev lockfile.Entry, class lockfile.DriftClass, used map[string]usage.Stat, scanAt time.Time) []timeline.Event {
	in := timeline.Input{
		InstalledAt: e.ModifiedAt,
		DriftDetail: driftDetail(class, prev, e),
		DriftDanger: class == lockfile.DriftClassMutated || class == lockfile.DriftClassBroken,
	}
	if prev.Approval != nil && prev.Approval.Status == "approved" {
		in.ApprovedAt = prev.Approval.At
		in.ApprovedBy = prev.Approval.By
	}
	// A content drift (not the initial add) is the milestone worth dating; we
	// only know it as of this scan, so we stamp it with the scan time and label
	// it "detected" in the domain.
	switch class {
	case lockfile.DriftClassMutated, lockfile.DriftClassBroken, lockfile.DriftClassUpdated:
		in.DriftedAt = scanAt
	}
	if st, ok := statFor(used, e); ok {
		in.FirstUsed = st.FirstUsed
		in.LastUsed = st.LastUsed
		in.UseCount = st.Count
	}
	return timeline.Build(in)
}

// reputationOf joins the opt-in community trust signal (H3) to an artifact by
// its content hash. nil when the corpus is absent or has no entry — a miss is
// "unknown," never a negative signal, so the UI simply shows nothing.
func reputationOf(contentHash string, rep reputation.Source) *DashReputation {
	sig, ok := rep.Lookup(contentHash)
	if !ok {
		return nil
	}
	d := &DashReputation{Trusters: sig.Trusters, Grade: string(sig.Grade())}
	if !sig.FirstSeen.IsZero() {
		d.FirstSeen = sig.FirstSeen.UTC().Format("2006-01-02")
	}
	return d
}

// livenessOf classifies how exercised an artifact is (F3), for the capability ×
// usage fusion on its findings. Runtime telemetry joins by artifact name — tool
// calls for MCP servers, activations for skills/subagents (F1b) — so any kind
// with a matching event presents positive evidence; one with none is Unknown,
// never falsely dormant.
func livenessOf(e lockfile.Entry, used map[string]usage.Stat, now time.Time) risk.Liveness {
	stat, found := statFor(used, e)
	return risk.Classify(stat, found, now)
}

// statFor joins an artifact to its usage stat in the kind-aware namespace: MCP
// servers on the bare name (the shim's tool-call key), every other kind through
// the activation namespace (the hook-fed key). This keeps a skill and an MCP
// server that share a name from ever sharing telemetry.
func statFor(used map[string]usage.Stat, e lockfile.Entry) (usage.Stat, bool) {
	if e.Type == artifact.TypeMCPServer {
		s, ok := used[e.Name]
		return s, ok
	}
	s, ok := used[usage.ActivationKey(e.Name)]
	return s, ok
}

// relativeAgo renders a coarse "3d ago" / "5h ago" / "just now" relative to the
// scan clock, for the at-a-glance usage line. Empty when either time is unknown.
func relativeAgo(t, now time.Time) string {
	if t.IsZero() || now.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h ago"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d ago"
	}
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

// isShadow reports an unaccounted artifact (B3): newly present (absent from the
// lockfile) and locally defined rather than pulled from a known registry or
// package source. npm/git/url/container sources are declared and resolvable, so
// they are never shadow; local and inline artifacts that no one locked are.
func isShadow(class lockfile.DriftClass, hasLocked bool, kind artifact.SourceKind) bool {
	if class != lockfile.DriftClassAdded && hasLocked {
		return false
	}
	switch kind {
	case artifact.SourceLocal, artifact.SourceInline:
		return true
	default:
		return false
	}
}

// shadowEntries returns the live inventory entries that are unaccounted (B3):
// present in the scan but not in the lockfile and not from a known registry —
// exactly the set the dashboard's orange banner counts. The bulk "account all"
// write path approves these into the lockfile.
func shadowEntries(current, locked lockfile.Lockfile) []lockfile.Entry {
	classes := lockfile.Classify(locked, current)
	hasLocked := map[string]bool{}
	for _, e := range locked.Artifacts {
		hasLocked[e.ID] = true
	}
	var out []lockfile.Entry
	for _, e := range current.Artifacts {
		if isShadow(classes[e.ID], hasLocked[e.ID], e.Source.Kind) {
			out = append(out, e)
		}
	}
	return out
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

func mapFindings(fs []finding.Finding, live risk.Liveness, locked lockfile.Entry, curHash string) []DashFinding {
	out := make([]DashFinding, 0, len(fs))
	for _, f := range fs {
		key := lockfile.FindingKey(f)
		df := DashFinding{
			ID:       key,
			Key:      key,
			RuleID:   f.RuleID,
			Pattern:  patternOf(f.RuleID),
			Severity: severityOf(f.Severity),
			OWASP:    f.OWASP,
			Title:    titleOf(f),
			Detail:   f.Explanation,
			Evidence: f.Snippet,
			Location: location(f),
			File:     f.File,
			Line:     f.Line,
			Liveness: string(live),
			RiskRank: risk.Rank(f.Severity, live),
			Reach:    string(reach.Classify(f.File)),
		}
		if ack := findAck(locked, key); ack != nil {
			df.Safe = true
			df.SafeBy = ack.By
			df.SafeAt = relativeStamp(ack.At)
			df.SafeStale = ack.Hash != "" && curHash != "" && ack.Hash != curHash
		}
		out = append(out, df)
	}
	return out
}

// orEmpty returns a non-nil slice so the JSON encodes [] rather than null —
// the dashboard's TS types treat these as always-present arrays, and a null
// crashes the capability view.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// findAck returns the "flagged safe" sign-off for a finding key on the locked
// entry, or nil when the finding is not flagged.
func findAck(locked lockfile.Entry, key string) *lockfile.FindingAck {
	for i := range locked.SafeFindings {
		if locked.SafeFindings[i].Key == key {
			return &locked.SafeFindings[i]
		}
	}
	return nil
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
