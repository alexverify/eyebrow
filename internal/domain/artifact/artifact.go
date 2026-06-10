// Package artifact defines the normalized internal model for every "thing"
// agentguard discovers across AI coding tools: skills, MCP servers, plugins,
// subagents, hooks, rules, and context files.
//
// Discovery adapters parse heterogeneous tool configs (JSON, JSONC, TOML) and
// normalize each entry into an Artifact. Downstream stages (resolve, hash,
// analyze) enrich the same value. This package is pure domain: no IO.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/agentguard/agentguard/internal/domain/finding"
)

// Type enumerates the kinds of artifacts agentguard tracks.
type Type string

const (
	TypeSkill     Type = "skill"
	TypeMCPServer Type = "mcp_server"
	TypePlugin    Type = "plugin"
	TypeSubagent  Type = "subagent"
	TypeHook      Type = "hook"
	TypeRules     Type = "rules"
	TypeContext   Type = "context"
)

// SourceKind describes how an artifact's code or content is obtained, which
// determines how the resolver pins it and what serves as its integrity anchor.
type SourceKind string

const (
	SourceNPM    SourceKind = "npm"    // anchor: pkg@version + npm integrity
	SourceGit    SourceKind = "git"    // anchor: commit SHA
	SourceURL    SourceKind = "url"    // anchor: URL + TLS cert SPKI pin
	SourceLocal  SourceKind = "local"  // anchor: directory content hash
	SourceInline SourceKind = "inline" // anchor: literal content hash
)

// Source captures the declaration of where an artifact comes from, plus the
// integrity anchors the resolver fills in.
type Source struct {
	Kind      SourceKind        `json:"kind"`
	Ref       string            `json:"ref,omitempty"`       // "pkg@1.2.3" | "git+https://…#sha" | URL | abs path
	Integrity string            `json:"integrity,omitempty"` // npm integrity (sha512-…) when available
	CertSPKI  string            `json:"certSpki,omitempty"`  // SPKI pin for remote (url) sources
	Command   string            `json:"command,omitempty"`   // for MCP servers: the spawn command
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"` // env keys that look like secrets are flagged, not stored verbatim
}

// Capabilities are the declared (config-stated) powers of an artifact. They
// seed the egress allowlist and sandbox profile in the runtime firewall.
type Capabilities struct {
	Exec       bool     `json:"exec,omitempty"`
	Network    []string `json:"network,omitempty"`    // allowed hosts
	Filesystem []string `json:"filesystem,omitempty"` // allowed paths
}

// FileRef records a single file within a multi-file artifact and its per-file
// hash, so verify can report exactly which file changed.
type FileRef struct {
	Path string `json:"path"` // POSIX-relative to the artifact root
	Hash string `json:"hash"` // lowercase hex SHA-256 (no prefix)
}

// Artifact is the normalized record for one discovered item. It accumulates
// data as it flows through the pipeline: discovery sets identity and Source;
// resolve fills integrity anchors; hash sets Files and ContentHash; analyze
// appends Findings.
type Artifact struct {
	ID             string            `json:"id"`   // stable: see MakeID
	Tool           string            `json:"tool"` // "claude-code" | "cursor" | "codex" | "gemini" | "opencode"
	Scope          string            `json:"scope"`
	Type           Type              `json:"type"`
	Name           string            `json:"name"`
	Source         Source            `json:"source"`
	Capabilities   Capabilities      `json:"capabilities"`
	Files          []FileRef         `json:"files,omitempty"`
	Findings       []finding.Finding `json:"findings,omitempty"`
	ContentHash    string            `json:"contentHash,omitempty"`
	DiscoveredFrom string            `json:"discoveredFrom,omitempty"` // the config file path
}

// MakeID returns a stable identifier derived from the tuple that uniquely
// names an artifact within the inventory. Two scans of an unchanged
// environment must yield the same ID, which is what lets verify match a
// current artifact against its locked counterpart.
func MakeID(tool, scope string, t Type, name string) string {
	h := sha256.New()
	for _, part := range []string{tool, scope, string(t), name} {
		h.Write([]byte(part))
		h.Write([]byte{0x00})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// MaxSeverity returns the highest finding severity on the artifact.
func (a Artifact) MaxSeverity() finding.Severity {
	return finding.Max(a.Findings)
}
