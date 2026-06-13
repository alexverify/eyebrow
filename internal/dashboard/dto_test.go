package dashboard

import (
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

func art(id, tool string, typ artifact.Type, name, hash string) artifact.Artifact {
	return artifact.Artifact{
		ID: id, Tool: tool, Type: typ, Name: name, ContentHash: hash,
		Source: artifact.Source{Kind: artifact.SourceNPM, Ref: "1.2.3"},
	}
}

func lf(arts ...artifact.Artifact) lockfile.Lockfile {
	return lockfile.Build(arts, time.Unix(1000, 0).UTC(), "agentguard/test")
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
	scan := BuildScan(cur, lockfile.Lockfile{}, nil)

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

	scan := BuildScan(current, lockedEntries, approvedSet(lockedEntries))

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

	scan := BuildScan(current, locked, approvedSet(locked))
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
	scan := BuildScan(lf(cur), locked, nil)
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
	scan := BuildScan(lf(a), lockfile.Lockfile{}, nil)
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
	scan := BuildScan(cur, lockfile.Lockfile{}, nil)
	if find(t, scan, "s").InstalledAt == "" {
		t.Error("installedAt should fall back to the scan timestamp when unknown")
	}
}
