package dashboard

import (
	"testing"
	"time"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/usage"
)

func art(id, tool string, typ artifact.Type, name, hash string) artifact.Artifact {
	return artifact.Artifact{
		ID: id, Tool: tool, Type: typ, Name: name, ContentHash: hash,
		Source: artifact.Source{Kind: artifact.SourceNPM, Ref: "1.2.3"},
	}
}

func lf(arts ...artifact.Artifact) lockfile.Lockfile {
	return lockfile.Build(arts, time.Unix(1000, 0).UTC(), "assay/test")
}

func find(t *testing.T, scan []DashArtifact, name string) DashArtifact {
	t.Helper()
	for _, a := range scan {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("artifact %q not in scan output", name)
	return DashArtifact{}
}

func TestBuildScanMapsKindAndAgent(t *testing.T) {
	cur := lf(
		art("a1", "claude-code", artifact.TypeMCPServer, "github", "sha256-x"),
		art("a2", "windsurf", artifact.TypeSkill, "linter", "sha256-y"),
	)
	scan := BuildScan(cur, lockfile.Lockfile{}, nil, nil)

	gh := find(t, scan, "github")
	if gh.Kind != "mcp" {
		t.Errorf("mcp_server should map to kind 'mcp', got %q", gh.Kind)
	}
	if gh.Agent != "Claude Code" {
		t.Errorf("tool should map to display name, got %q", gh.Agent)
	}
	lint := find(t, scan, "linter")
	if lint.Kind != "skill" || lint.Agent != "Windsurf" {
		t.Errorf("windsurf skill mapping: %+v", lint)
	}
	if gh.Version != "1.2.3" {
		t.Errorf("npm version should derive from Source.Ref, got %q", gh.Version)
	}
}

func TestBuildScanDriftStatuses(t *testing.T) {
	// locked snapshot: github (approved+signed), db (no approval)
	lockedGithub := art("a1", "claude-code", artifact.TypeMCPServer, "github", "sha256-old")
	lockedGithub.ContentHash = "sha256-locked"
	lockedDB := art("a2", "cursor", artifact.TypeMCPServer, "db", "sha256-db")

	lockedEntries := lf(lockedGithub, lockedDB)
	lockedEntries.Artifacts[0].Approval = &lockfile.Approval{Status: "approved", Sig: "ed25519:x"}
	// db has no approval

	// current: github drifted (hash moved), db unchanged, newtool added
	curGithub := art("a1", "claude-code", artifact.TypeMCPServer, "github", "sha256-locked")
	curGithub.ContentHash = "sha256-NEW" // moved → drifted
	current := lf(
		curGithub,
		art("a2", "cursor", artifact.TypeMCPServer, "db", "sha256-db"), // unchanged
		art("a3", "codex", artifact.TypeSkill, "fresh", "sha256-z"),    // added → new
	)

	scan := BuildScan(current, lockedEntries, approvedSet(lockedEntries), nil)

	if s := find(t, scan, "github").Drift; s != "drifted" {
		t.Errorf("github moved hash → drifted, got %q", s)
	}
	if s := find(t, scan, "fresh").Drift; s != "new" {
		t.Errorf("fresh artifact absent from lockfile → new, got %q", s)
	}
	if s := find(t, scan, "db").Drift; s != "unsigned" {
		t.Errorf("db present+matching but unapproved → unsigned, got %q", s)
	}
}

func TestBuildScanVerifiedWhenApprovedAndMatching(t *testing.T) {
	a := art("a1", "claude-code", artifact.TypeSkill, "ok-skill", "sha256-same")
	locked := lf(a)
	locked.Artifacts[0].Approval = &lockfile.Approval{Status: "approved", Sig: "ed25519:x"}
	current := lf(a)

	scan := BuildScan(current, locked, approvedSet(locked), nil)
	if s := find(t, scan, "ok-skill").Drift; s != "verified" {
		t.Errorf("approved + matching hash → verified, got %q", s)
	}
	if find(t, scan, "ok-skill").LockedHash == "" {
		t.Error("verified artifact should carry its locked hash")
	}
}

func TestBuildScanLockedHashJoin(t *testing.T) {
	locked := lf(func() artifact.Artifact {
		a := art("a1", "claude-code", artifact.TypeSkill, "s", "x")
		a.ContentHash = "sha256-LOCKED"
		return a
	}())
	cur := func() artifact.Artifact {
		a := art("a1", "claude-code", artifact.TypeSkill, "s", "x")
		a.ContentHash = "sha256-CURRENT"
		return a
	}()
	scan := BuildScan(lf(cur), locked, nil, nil)
	got := find(t, scan, "s")
	if got.Hash != "sha256-CURRENT" || got.LockedHash != "sha256-LOCKED" {
		t.Errorf("hash join wrong: hash=%q locked=%q", got.Hash, got.LockedHash)
	}
}

func TestBuildScanMapsFindings(t *testing.T) {
	a := art("a1", "claude-code", artifact.TypeSkill, "evil", "sha256-x")
	a.Findings = []finding.Finding{{
		RuleID: "RCE-PIPE-EXEC", Severity: finding.SeverityCritical,
		File: "hooks/postinstall.sh", Line: 4,
		Snippet: "curl x | sh", Explanation: "pipes a remote script into a shell",
	}}
	scan := BuildScan(lf(a), lockfile.Lockfile{}, nil, nil)
	f := find(t, scan, "evil").Findings
	if len(f) != 1 {
		t.Fatalf("got %d findings", len(f))
	}
	if f[0].Pattern != "remote-code-exec" {
		t.Errorf("RCE-PIPE-EXEC should map to remote-code-exec, got %q", f[0].Pattern)
	}
	if f[0].Severity != "critical" || f[0].Location != "hooks/postinstall.sh:4" {
		t.Errorf("finding mapping: %+v", f[0])
	}
	if f[0].Title == "" || f[0].Detail == "" || f[0].Evidence == "" {
		t.Errorf("finding must carry title/detail/evidence: %+v", f[0])
	}
}

func TestBuildScanInstalledAtFallsBackToScanTime(t *testing.T) {
	cur := lf(art("a1", "claude-code", artifact.TypeSkill, "s", "x"))
	scan := BuildScan(cur, lockfile.Lockfile{}, nil, nil)
	if find(t, scan, "s").InstalledAt == "" {
		t.Error("installedAt should fall back to the scan timestamp when unknown")
	}
}

func TestBuildScanInstalledAtUsesModTime(t *testing.T) {
	a := art("a1", "claude-code", artifact.TypeSkill, "s", "x")
	a.ModifiedAt = time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC)
	scan := BuildScan(lf(a), lockfile.Lockfile{}, nil, nil)
	if got := find(t, scan, "s").InstalledAt; got != "2026-03-01 09:30" {
		t.Errorf("installedAt should use the artifact mtime, got %q", got)
	}
}

func TestBuildScanDetailFields(t *testing.T) {
	a := art("a1", "claude-code", artifact.TypeMCPServer, "db", "sha256-x")
	a.Scope = "project:."
	a.DiscoveredFrom = ".mcp.json"
	a.Source = artifact.Source{
		Kind: artifact.SourceNPM, Ref: "1.2.3", Integrity: "sha512-abc",
		Command: "npx", Args: []string{"-y", "db-mcp"},
		Env: map[string]string{"DB_TOKEN": "secret-value", "DB_HOST": "h"},
	}
	a.Capabilities = artifact.Capabilities{Exec: true, Network: []string{"api.db.example"}}
	a.Files = []artifact.FileRef{{Path: "server.js", Hash: "deadbeef"}}

	d := find(t, BuildScan(lf(a), lockfile.Lockfile{}, nil, nil), "db")

	if d.Scope != "project:." || d.DiscoveredFrom != ".mcp.json" || d.SourceKind != "npm" {
		t.Errorf("provenance fields: %+v", d)
	}
	if d.Command != "npx" || len(d.Args) != 2 || d.Integrity != "sha512-abc" {
		t.Errorf("source fields: %+v", d)
	}
	// env exposes KEYS ONLY, never values, sorted.
	if len(d.EnvKeys) != 2 || d.EnvKeys[0] != "DB_HOST" || d.EnvKeys[1] != "DB_TOKEN" {
		t.Errorf("envKeys = %v (must be sorted names only)", d.EnvKeys)
	}
	if !d.Capabilities.Exec || len(d.Capabilities.Network) != 1 {
		t.Errorf("capabilities: %+v", d.Capabilities)
	}
	if len(d.Files) != 1 || d.Files[0].Path != "server.js" {
		t.Errorf("file manifest: %+v", d.Files)
	}
}

func TestBuildScanApprovalDetail(t *testing.T) {
	a := art("a1", "claude-code", artifact.TypeSkill, "s", "x")
	locked := lf(a)
	locked.Artifacts[0].Approval = &lockfile.Approval{
		Status: "approved", By: "alice", At: time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC), Sig: "ed25519:x",
	}
	d := find(t, BuildScan(lf(a), locked, approvedSet(locked), nil), "s")
	if d.Approval == nil || d.Approval.By != "alice" || !d.Approval.Signed {
		t.Errorf("approval detail: %+v", d.Approval)
	}
}

func TestBuildScanTrustVerdict(t *testing.T) {
	clean := art("a1", "claude-code", artifact.TypeSkill, "linter", "sha256-x")
	clean.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-AAA"}
	locked := lf(clean)
	locked.Artifacts[0].Approval = &lockfile.Approval{Status: "approved", Sig: "ed25519:x"}

	scan := BuildScan(lf(clean), locked, approvedSet(locked), nil)
	got := find(t, scan, "linter")
	if got.Verdict != "trusted" || got.Trust != 100 {
		t.Fatalf("clean signed npm → trusted/100, got %q/%d", got.Verdict, got.Trust)
	}
	if len(got.TrustReasons) == 0 {
		t.Fatalf("trust reasons must be populated")
	}
}

func TestBuildScanUpdatedVsMutatedStatus(t *testing.T) {
	lockedMut := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-old")
	lockedMut.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	curMut := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-NEW")
	curMut.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}

	lockedUpd := art("u1", "cursor", artifact.TypeSkill, "fmt", "sha256-old")
	lockedUpd.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	curUpd := art("u1", "cursor", artifact.TypeSkill, "fmt", "sha256-new")
	curUpd.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "2.0.0", Integrity: "sha512-B"}

	scan := BuildScan(lf(curMut, curUpd), lf(lockedMut, lockedUpd), nil, nil)
	if s := find(t, scan, "db").Drift; s != "drifted" {
		t.Errorf("same-version content move → drifted, got %q", s)
	}
	if s := find(t, scan, "fmt").Drift; s != "updated" {
		t.Errorf("version+content move → updated, got %q", s)
	}
	if d := find(t, scan, "fmt").DriftDetail; d == "" {
		t.Errorf("updated artifact should carry a DriftDetail")
	}
}

func TestBuildScanUsageJoinsByServerNameForMCP(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	cur := art("a1", "claude-code", artifact.TypeMCPServer, "weather", "sha256-x")
	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "assay/test")

	used := map[string]usage.Stat{
		"weather": {
			FirstUsed: scanAt.Add(-48 * time.Hour),
			LastUsed:  scanAt.Add(-3 * time.Hour),
			Count:     7,
		},
	}
	got := find(t, BuildScan(current, lockfile.Lockfile{}, nil, used), "weather")
	if got.Usage == nil {
		t.Fatalf("MCP server with audit telemetry should carry Usage")
	}
	if got.Usage.Count != 7 {
		t.Errorf("Usage.Count = %d, want 7", got.Usage.Count)
	}
	if got.Usage.LastUsedRel != "3h ago" {
		t.Errorf("Usage.LastUsedRel = %q, want \"3h ago\"", got.Usage.LastUsedRel)
	}
}

func TestBuildScanNoUsageForNonMCPOrUntracked(t *testing.T) {
	cur := lf(
		art("s1", "claude-code", artifact.TypeSkill, "weather", "sha256-x"), // same name, not MCP
		art("m1", "claude-code", artifact.TypeMCPServer, "lonely", "sha256-y"),
	)
	used := map[string]usage.Stat{"weather": {Count: 3, LastUsed: time.Unix(2000, 0)}}
	scan := BuildScan(cur, lockfile.Lockfile{}, nil, used)
	if find(t, scan, "weather").Usage != nil {
		t.Errorf("a skill must not inherit an MCP server's telemetry by name")
	}
	if find(t, scan, "lonely").Usage != nil {
		t.Errorf("an MCP server with no telemetry should have nil Usage")
	}
}

func TestBuildScanSleeperOnDormantDriftThenRun(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// Locked vs current: same pinned ref, different content hash → mutated drift.
	locked := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-old")
	locked.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	cur := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-NEW")
	cur.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	cur.ModifiedAt = scanAt.Add(-60 * 24 * time.Hour) // installed ~60 days ago

	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "assay/test")
	used := map[string]usage.Stat{
		"db": {FirstUsed: scanAt.Add(-24 * time.Hour), LastUsed: scanAt, Count: 1}, // first run yesterday
	}
	got := find(t, BuildScan(current, lf(locked), nil, used), "db")
	if got.Sleeper == nil {
		t.Fatalf("dormant-then-active triple should flag a sleeper")
	}
	if got.Sleeper.DormantDays < 14 {
		t.Errorf("DormantDays = %d, want the full dormancy", got.Sleeper.DormantDays)
	}
}

func TestBuildScanNoSleeperWithoutDrift(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	cur := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-same")
	cur.ModifiedAt = scanAt.Add(-60 * 24 * time.Hour)
	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "assay/test")
	used := map[string]usage.Stat{"db": {FirstUsed: scanAt.Add(-24 * time.Hour), Count: 1}}
	// Locked == current content → no drift → no sleeper even though dormant+used.
	if got := find(t, BuildScan(current, lf(cur), nil, used), "db"); got.Sleeper != nil {
		t.Errorf("sleeper must not fire without drift: %+v", got.Sleeper)
	}
}

func TestBuildScanTimelineRibbon(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	locked := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-old")
	locked.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	cur := art("m1", "cursor", artifact.TypeMCPServer, "db", "sha256-NEW")
	cur.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	cur.ModifiedAt = scanAt.Add(-40 * 24 * time.Hour)

	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "assay/test")
	used := map[string]usage.Stat{
		"db": {FirstUsed: scanAt.Add(-2 * 24 * time.Hour), LastUsed: scanAt.Add(-1 * time.Hour), Count: 5},
	}
	got := find(t, BuildScan(current, lf(locked), nil, used), "db")
	if len(got.Timeline) == 0 {
		t.Fatalf("a drifted, used MCP server should have a timeline ribbon")
	}
	// Must be time-ordered and lead with the install.
	if got.Timeline[0].Kind != "installed" {
		t.Errorf("ribbon should start with installed, got %q", got.Timeline[0].Kind)
	}
	for i := 1; i < len(got.Timeline); i++ {
		if got.Timeline[i].At.Before(got.Timeline[i-1].At) {
			t.Errorf("timeline out of order at %d", i)
		}
	}
	var sawDrift bool
	for _, e := range got.Timeline {
		if e.Kind == "drifted" {
			sawDrift = true
		}
	}
	if !sawDrift {
		t.Errorf("a mutated artifact should carry a drift milestone: %+v", got.Timeline)
	}
}

func TestBuildScanFindingLivenessFusion(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// Two MCP servers with an identical high finding: one invoked yesterday,
	// one with no telemetry. The live one's finding must rank higher (F3).
	live := art("m1", "cursor", artifact.TypeMCPServer, "live-srv", "sha256-a")
	live.Findings = []finding.Finding{{RuleID: "R1", Severity: finding.SeverityHigh, Explanation: "x"}}
	cold := art("m2", "cursor", artifact.TypeMCPServer, "cold-srv", "sha256-b")
	cold.Findings = []finding.Finding{{RuleID: "R1", Severity: finding.SeverityHigh, Explanation: "x"}}

	current := lockfile.Build([]artifact.Artifact{live, cold}, scanAt, "assay/test")
	used := map[string]usage.Stat{
		"live-srv": {FirstUsed: scanAt.Add(-48 * time.Hour), LastUsed: scanAt.Add(-24 * time.Hour), Count: 3},
	}
	scan := BuildScan(current, lockfile.Lockfile{}, nil, used)

	lf := find(t, scan, "live-srv").Findings[0]
	cf := find(t, scan, "cold-srv").Findings[0]
	if lf.Liveness != "live" {
		t.Errorf("recently-invoked server's finding should be live, got %q", lf.Liveness)
	}
	if cf.Liveness != "unknown" {
		t.Errorf("untracked server's finding should be unknown, got %q", cf.Liveness)
	}
	if lf.RiskRank <= cf.RiskRank {
		t.Errorf("live finding rank (%d) should exceed dormant (%d)", lf.RiskRank, cf.RiskRank)
	}
}

func TestBuildScanFindingLivenessUnknownForSkill(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// A skill shares a name with a used server; it must NOT inherit liveness —
	// telemetry joins by MCP server name only.
	skill := art("s1", "claude-code", artifact.TypeSkill, "shared", "sha256-x")
	skill.Findings = []finding.Finding{{RuleID: "R1", Severity: finding.SeverityMedium, Explanation: "x"}}
	current := lockfile.Build([]artifact.Artifact{skill}, scanAt, "assay/test")
	used := map[string]usage.Stat{"shared": {LastUsed: scanAt, Count: 99}}
	got := find(t, BuildScan(current, lockfile.Lockfile{}, nil, used), "shared").Findings[0]
	if got.Liveness != "unknown" {
		t.Errorf("a skill must not inherit MCP telemetry by name, got %q", got.Liveness)
	}
}

func TestBuildScanFindingReachability(t *testing.T) {
	a := art("r1", "claude-code", artifact.TypeSkill, "mixed", "sha256-x")
	a.Findings = []finding.Finding{
		{RuleID: "R1", Severity: finding.SeverityHigh, File: "src/collect.js", Line: 10},
		{RuleID: "R2", Severity: finding.SeverityHigh, File: "test/collect.test.js", Line: 5},
	}
	got := find(t, BuildScan(lf(a), lockfile.Lockfile{}, nil, nil), "mixed").Findings
	by := map[string]string{}
	for _, f := range got {
		by[f.RuleID] = f.Reach
	}
	if by["R1"] != "reachable" {
		t.Errorf("a src/ finding should be reachable, got %q", by["R1"])
	}
	if by["R2"] != "inert" {
		t.Errorf("a finding in a test path should be inert, got %q", by["R2"])
	}
}

func TestBuildScanCapabilityDiff(t *testing.T) {
	locked := art("c1", "claude-code", artifact.TypeSkill, "grower", "sha256-old")
	locked.Capabilities = artifact.Capabilities{Network: []string{"api.openai.com"}}
	cur := art("c1", "claude-code", artifact.TypeSkill, "grower", "sha256-new")
	cur.Capabilities = artifact.Capabilities{
		Network:    []string{"api.openai.com", "evil.example"},
		Filesystem: []string{"~/.aws"},
	}
	scan := BuildScan(lf(cur), lf(locked), nil, nil)
	got := find(t, scan, "grower").Capabilities
	if len(got.AddedNetwork) != 1 || got.AddedNetwork[0] != "evil.example" {
		t.Errorf("added network host should surface: %+v", got.AddedNetwork)
	}
	if len(got.SensitiveAdded) != 1 || got.SensitiveAdded[0] != "~/.aws" {
		t.Errorf("added secret path should be flagged: %+v", got.SensitiveAdded)
	}
}

func TestBuildScanShadowDetection(t *testing.T) {
	// A locally-defined hook, newly present and never locked → shadow.
	shadow := art("h1", "claude-code", artifact.TypeHook, "mystery-hook", "sha256-x")
	shadow.Source = artifact.Source{Kind: artifact.SourceInline, Ref: "echo hi"}
	// A new npm artifact is declared/resolvable → never shadow.
	declared := art("n1", "cursor", artifact.TypeMCPServer, "db", "sha256-y")

	scan := BuildScan(lf(shadow, declared), lockfile.Lockfile{}, nil, nil)
	if !find(t, scan, "mystery-hook").Shadow {
		t.Error("a new, locally-defined artifact should be flagged shadow")
	}
	if find(t, scan, "db").Shadow {
		t.Error("a new npm artifact is declared and must not be flagged shadow")
	}

	// Once locked, the same local artifact is accounted for → not shadow.
	locked := lf(shadow)
	if find(t, BuildScan(lf(shadow), locked, nil, nil), "mystery-hook").Shadow {
		t.Error("a locked local artifact is accounted for and must not be shadow")
	}
}

func TestBuildScanFileChangesOnDrift(t *testing.T) {
	locked := art("d1", "claude-code", artifact.TypeSkill, "pdf", "sha256-old")
	locked.Files = []artifact.FileRef{
		{Path: "index.js", Hash: "a"},
		{Path: "README.md", Hash: "b"},
	}
	cur := art("d1", "claude-code", artifact.TypeSkill, "pdf", "sha256-new")
	cur.Files = []artifact.FileRef{
		{Path: "index.js", Hash: "a"},             // unchanged
		{Path: "hooks/postinstall.sh", Hash: "c"}, // added
		// README.md removed
	}

	got := find(t, BuildScan(lf(cur), lf(locked), nil, nil), "pdf")
	if got.FileChanges == nil {
		t.Fatal("drifted artifact should carry a FileChanges diff")
	}
	if len(got.FileChanges.Added) != 1 || got.FileChanges.Added[0] != "hooks/postinstall.sh" {
		t.Errorf("Added = %v, want [hooks/postinstall.sh]", got.FileChanges.Added)
	}
	if len(got.FileChanges.Removed) != 1 || got.FileChanges.Removed[0] != "README.md" {
		t.Errorf("Removed = %v, want [README.md]", got.FileChanges.Removed)
	}
}

func TestBuildScanNoFileChangesWhenUnchanged(t *testing.T) {
	a := art("d2", "claude-code", artifact.TypeSkill, "stable", "sha256-x")
	a.Files = []artifact.FileRef{{Path: "index.js", Hash: "a"}}
	locked := lf(a)
	locked.Artifacts[0].Approval = &lockfile.Approval{Status: "approved", Sig: "ed25519:x"}

	got := find(t, BuildScan(lf(a), locked, approvedSet(locked), nil), "stable")
	if got.FileChanges != nil {
		t.Errorf("unchanged artifact must not carry a FileChanges diff, got %+v", got.FileChanges)
	}
}

func TestBuildScanNoFileChangesForNewArtifact(t *testing.T) {
	// A brand-new artifact (no locked prior) has nothing to diff against.
	a := art("d3", "claude-code", artifact.TypeSkill, "fresh", "sha256-x")
	a.Files = []artifact.FileRef{{Path: "index.js", Hash: "a"}}
	got := find(t, BuildScan(lf(a), lockfile.Lockfile{}, nil, nil), "fresh")
	if got.FileChanges != nil {
		t.Errorf("new artifact has no prior manifest to diff, got %+v", got.FileChanges)
	}
}

func TestBuildScanQuarantineAndProvenance(t *testing.T) {
	a := art("q1", "claude-code", artifact.TypeSkill, "suspect", "sha256-x")
	a.Source = artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"}
	locked := lf(a)
	locked.Artifacts[0].Quarantined = true

	scan := BuildScan(lf(a), locked, nil, nil)
	got := find(t, scan, "suspect")
	if !got.Quarantined {
		t.Errorf("quarantined state should surface")
	}
	if got.Verdict != "quarantine" {
		t.Errorf("quarantined artifact verdict should be 'quarantine', got %q", got.Verdict)
	}
	// pinned + integrity, unsigned → provenance level 2 of 4
	if got.Provenance.Level != 2 || got.Provenance.Max != 4 {
		t.Errorf("provenance ladder = %d/%d, want 2/4", got.Provenance.Level, got.Provenance.Max)
	}
}
