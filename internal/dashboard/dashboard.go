// Package dashboard serves a local, read-only web view of what assay sees
// on this machine: the inventory, drift against the lockfile, findings, and the
// MCP shim's audit timeline. It is the Go backend of the dashboard — the UI is
// a Next.js app embedded as a static export (see assets/).
//
// It binds loopback only and rejects requests whose Host header is not a
// loopback name, so a malicious page cannot drive it via DNS rebinding. There
// is no auth because there is no remotely reachable surface — a supply-chain
// tool must not expose an unauthenticated control plane.
package dashboard

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"github.com/alexverify/assay/internal/adapters/auditlog"
	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/domain/alert"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/policy"
	"github.com/alexverify/assay/internal/domain/posture"
	"github.com/alexverify/assay/internal/domain/reputation"
	"github.com/alexverify/assay/internal/domain/usage"
)

//go:embed all:assets
var assetsFS embed.FS

// Deps are the data sources the dashboard renders. Keeping them as functions
// lets the CLI wire in the real scan/verify/audit pipeline while tests inject
// fixtures, with no filesystem or subprocess access.
type Deps struct {
	// Inventory builds the current live inventory (the scan pipeline).
	Inventory func(context.Context) (lockfile.Lockfile, error)
	// Locked returns the committed lockfile, or a zero value when none exists.
	Locked func(context.Context) (lockfile.Lockfile, error)
	// Audit reads matching audit events.
	Audit func(auditlog.Filter) ([]audit.Event, error)
	// ApprovalVerifier checks each locked approval's signature against trusted
	// keys, so the dashboard distinguishes "verified" from merely "approved".
	// Optional: when nil, an approval bearing a signature is treated as trusted.
	ApprovalVerifier ports.ApprovalVerifier
	// Mutate applies a change to the committed lockfile under a read-modify-write,
	// backing the approve/quarantine/freeze write endpoints. Optional: when nil,
	// those endpoints are disabled and the dashboard is strictly read-only.
	Mutate func(ctx context.Context, fn func(lf *lockfile.Lockfile) error) error
	// Policy returns the committed policy, backing the Policy tab and the egress
	// allowlist view. Optional: when nil, GET /api/policy returns the default.
	Policy func(context.Context) (policy.Policy, error)
	// MutatePolicy applies a change to the committed policy file under a
	// read-modify-write, backing the policy-editor (C3), mute (C4), and egress
	// allowlist (D2) write endpoints. Optional: when nil they are disabled.
	MutatePolicy func(ctx context.Context, fn func(p *policy.Policy) error) error
	// History returns the counts-only posture trend (E2). Optional: when nil,
	// GET /api/history returns an empty trend.
	History func(context.Context) ([]posture.Posture, error)
	// Fleet returns the aggregated team blast-radius (G1) from committed
	// snapshots. Optional: when nil, GET /api/fleet returns an empty report.
	Fleet func(context.Context) (fleet.Report, error)
	// Conformance returns the fleet's policy-compliance rollup (G3): which
	// machines run blocked/unapproved artifacts. Optional: nil → empty.
	Conformance func(context.Context) (fleet.Conformance, error)
	// Alerts returns the org's team-level alerts (4d): drift, quarantine, blocked
	// egress, denied tool calls. Optional: nil → empty (the Alerts panel hides).
	Alerts func(context.Context) ([]alert.Alert, error)
	// Reputation resolves the opt-in community trust corpus (H3) for a set of
	// content hashes — from a local file or a live hash-only service (H3b).
	// Optional: when nil, no reputation signal is shown.
	Reputation func(hashes []string) (reputation.Source, error)
	// Blobs returns the captured bytes (path → content) for a content hash,
	// backing the line-level drift diff (H1b), or nil when that hash has no
	// stored baseline. Optional: when nil, the scan view falls back to the
	// content-free file-name list.
	Blobs func(contentHash string) (map[string][]byte, error)
	// Static overrides the embedded UI assets (used in tests); nil uses the
	// embedded Next.js export.
	Static fs.FS
}

// Server renders the dashboard.
type Server struct {
	deps   Deps
	static fs.FS
	token  string
}

// New constructs a Server. It mints a single random token that gates the write
// endpoints: a malicious page in the user's browser can issue a cross-origin
// POST but cannot read GET /api/token (same-origin policy), so it cannot forge
// the X-Assay-Token header. Combined with the loopback-Host guard, this
// keeps the mutating surface same-origin only.
func New(d Deps) *Server {
	static := d.Static
	if static == nil {
		sub, err := fs.Sub(assetsFS, "assets")
		if err == nil {
			static = sub
		}
	}
	return &Server{deps: d, static: static, token: randomToken()}
}

// Token returns the per-process write token (printed at launch).
func (s *Server) Token() string { return s.token }

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// Handler returns the HTTP handler: JSON under /api, the embedded UI elsewhere,
// all behind the loopback-Host guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/inventory", s.handleInventory)
	mux.HandleFunc("/api/drift", s.handleDrift)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/token", s.handleToken)
	mux.HandleFunc("/api/approve", s.handleApprove)
	mux.HandleFunc("/api/quarantine", s.handleQuarantine)
	mux.HandleFunc("/api/freeze", s.handleFreeze)
	mux.HandleFunc("/api/policy", s.handlePolicy)
	mux.HandleFunc("/api/mute", s.handleMute)
	mux.HandleFunc("/api/egress-allow", s.handleEgressAllow)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/fleet", s.handleFleet)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	if s.static != nil {
		mux.Handle("/", http.FileServer(http.FS(s.static)))
	}
	return loopbackOnly(mux)
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	lf, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, lf)
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	current, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	locked, err := s.deps.Locked(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, lockfile.Compare(locked, current))
}

// handleScan assembles the dashboard-shaped view (the UI's primary data
// source): the live inventory joined with the locked snapshot, with drift
// status, kind/agent mapping, and findings categorized for display.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	current, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	locked, err := s.deps.Locked(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	arts := BuildScan(current, locked, s.approvedSet(locked), s.usageSummary(), s.reputationSource(inventoryHashes(current)))
	AttachLineDiffs(arts, s.deps.Blobs)
	writeJSON(w, struct {
		Artifacts []DashArtifact `json:"artifacts"`
	}{Artifacts: arts})
}

// inventoryHashes collects the content hashes of the current inventory, the keys
// a reputation lookup needs (whether served from a local corpus or a live
// hash-only service).
func inventoryHashes(lf lockfile.Lockfile) []string {
	out := make([]string, 0, len(lf.Artifacts))
	for _, e := range lf.Artifacts {
		if e.ContentHash != "" {
			out = append(out, e.ContentHash)
		}
	}
	return out
}

// reputationSource resolves the opt-in community trust corpus (H3) for the given
// hashes — from a local file or a live hash-only lookup (H3b), per the wired
// dep. A nil dep or a load error yields an empty corpus — the signal is
// supplementary, so it must never fail the scan view; a miss simply shows no
// reputation.
func (s *Server) reputationSource(hashes []string) reputation.Source {
	if s.deps.Reputation == nil {
		return nil
	}
	src, err := s.deps.Reputation(hashes)
	if err != nil {
		return nil
	}
	return src
}

// usageSummary reads the runtime audit log and folds it into per-artifact
// invocation stats (F1). A nil Audit dep or a read error yields no telemetry —
// usage is supplementary, so it must never fail the scan view.
//
// It reads all events (no kind filter) so both MCP tool calls and the hook-fed
// activation events of skills/subagents/plugins count; usage.Summarize selects
// the invocation kinds and ignores the rest.
func (s *Server) usageSummary() map[string]usage.Stat {
	if s.deps.Audit == nil {
		return nil
	}
	events, err := s.deps.Audit(auditlog.Filter{})
	if err != nil {
		return nil
	}
	return usage.Summarize(events)
}

// approvedSet returns the IDs of locked artifacts whose approval is trusted.
// With a verifier, "trusted" means a valid signature from a trusted key; without
// one, an approval merely bearing a signature is accepted (dev fallback).
func (s *Server) approvedSet(locked lockfile.Lockfile) map[string]bool {
	if s.deps.ApprovalVerifier == nil {
		return approvedSet(locked)
	}
	out := make(map[string]bool)
	for _, e := range locked.Artifacts {
		if e.Approval != nil && e.Approval.Status == "approved" &&
			s.deps.ApprovalVerifier.VerifyApproval(e) == nil {
			out[e.ID] = true
		}
	}
	return out
}

// handleToken returns the write token to the same-origin UI. A cross-origin
// page can request this but cannot read the response (same-origin policy), so
// it never learns the token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, struct {
		Token          string `json:"token"`
		Writable       bool   `json:"writable"`
		PolicyWritable bool   `json:"policyWritable"`
	}{Token: s.token, Writable: s.deps.Mutate != nil, PolicyWritable: s.deps.MutatePolicy != nil})
}

// markRequest is the body of a write endpoint: which artifact, and whether to
// set or clear the flag/approval.
type markRequest struct {
	ID string `json:"id"`
	On bool   `json:"on"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) {
		if on {
			e.Approval = &lockfile.Approval{Status: "approved", By: "dashboard"}
		} else {
			e.Approval = nil
		}
	})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) { e.Quarantined = on })
}

func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) { e.Frozen = on })
}

// mutate is the shared, token-guarded write path: it applies set to the entry
// whose ID matches the request body, persisting via Deps.Mutate.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, set func(*lockfile.Entry, bool)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Assay-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return
	}
	if s.deps.Mutate == nil {
		http.Error(w, "dashboard is read-only (no lockfile to write)", http.StatusForbidden)
		return
	}
	var body markRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	found := false
	err := s.deps.Mutate(r.Context(), func(lf *lockfile.Lockfile) error {
		for i := range lf.Artifacts {
			if lf.Artifacts[i].ID == body.ID {
				set(&lf.Artifacts[i], body.On)
				found = true
				return nil
			}
		}
		return fmt.Errorf("artifact %q not in the lockfile", body.ID)
	})
	if err != nil {
		httpError(w, err)
		return
	}
	if !found {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// handleHistory serves the posture trend (E2) for the dashboard sparkline.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	var hist []posture.Posture
	if s.deps.History != nil {
		got, err := s.deps.History(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		hist = got
	}
	writeJSON(w, struct {
		History []posture.Posture `json:"history"`
	}{History: hist})
}

// handleAlerts serves the org's team-level alerts (4d). Empty when no Alerts dep
// is wired (e.g. the local dashboard with no control plane).
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := []alert.Alert{}
	if s.deps.Alerts != nil {
		got, err := s.deps.Alerts(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		if got != nil {
			alerts = got
		}
	}
	writeJSON(w, struct {
		Alerts []alert.Alert `json:"alerts"`
	}{Alerts: alerts})
}

// handleFleet serves the aggregated team blast-radius (G1): which artifacts are
// installed across how many machines, and where they have drifted. Built from
// committed snapshots — no live telemetry upload, same offline-first contract
// as the rest of the dashboard.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	var rep fleet.Report
	if s.deps.Fleet != nil {
		got, err := s.deps.Fleet(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		rep = got
	}
	var con fleet.Conformance
	if s.deps.Conformance != nil {
		got, err := s.deps.Conformance(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		con = got
	}
	// Embed the report (owners/artifacts/exposures/grid) and add conformance so
	// the Fleet tab gets blast radius (G1), heatmap (G2), and compliance (G3) in
	// one fetch.
	writeJSON(w, struct {
		fleet.Report
		Conformance fleet.Conformance `json:"conformance"`
	}{Report: rep, Conformance: con})
}

// handlePolicy serves the committed policy (GET) and edits its allow/block
// lists (POST, token-guarded) — the Policy tab (C3).
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p := policy.Default()
		if s.deps.Policy != nil {
			got, err := s.deps.Policy(r.Context())
			if err != nil {
				httpError(w, err)
				return
			}
			p = got
		}
		writeJSON(w, p)
		return
	}
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		AllowPublishers []string `json:"allowPublishers"`
		BlockPublishers []string `json:"blockPublishers"`
		BlockArtifacts  []string `json:"blockArtifacts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		p.AllowPublishers = cleanList(body.AllowPublishers)
		p.BlockPublishers = cleanList(body.BlockPublishers)
		p.BlockArtifacts = cleanList(body.BlockArtifacts)
		return nil
	})
}

// handleMute appends a finding-suppression with a rationale to the policy (C4).
func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
		By     string `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Rule == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.By == "" {
		body.By = "dashboard"
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		for _, m := range p.Mutes {
			if m.Rule == body.Rule {
				return nil // already muted — idempotent
			}
		}
		p.Mutes = append(p.Mutes, policy.Mute{Rule: body.Rule, Reason: body.Reason, By: body.By})
		return nil
	})
}

// handleEgressAllow adds a host to a server's egress allowlist (D2). The proxy
// enforces the same per-server rule via policy.DecideHost.
func (s *Server) handleEgressAllow(w http.ResponseWriter, r *http.Request) {
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		Server string `json:"server"`
		Host   string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Server == "" || body.Host == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		if p.MCP.Servers == nil {
			p.MCP.Servers = map[string]policy.ToolRule{}
		}
		rule := p.MCP.Servers[body.Server]
		for _, h := range rule.AllowHosts {
			if h == body.Host {
				return nil // already allowed — idempotent
			}
		}
		rule.AllowHosts = append(rule.AllowHosts, body.Host)
		p.MCP.Servers[body.Server] = rule
		return nil
	})
}

// allowPolicyWrite enforces POST + the write token + a writable policy, the
// shared guard for the policy-mutating endpoints. It writes the error response
// and returns false when the request must be refused.
func (s *Server) allowPolicyWrite(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if r.Header.Get("X-Assay-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return false
	}
	if s.deps.MutatePolicy == nil {
		http.Error(w, "dashboard is read-only (no policy to write)", http.StatusForbidden)
		return false
	}
	return true
}

// applyPolicy runs fn under the read-modify-write and reports the outcome.
func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request, fn func(*policy.Policy) error) {
	if err := s.deps.MutatePolicy(r.Context(), fn); err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// cleanList trims whitespace and drops empty entries from a user-supplied list.
func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	f := auditlog.Filter{
		Server: r.URL.Query().Get("server"),
		Tool:   r.URL.Query().Get("tool"),
		Status: r.URL.Query().Get("status"),
		Kind:   audit.Kind(r.URL.Query().Get("kind")),
	}
	events, err := s.deps.Audit(f)
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, struct {
		Events  []audit.Event    `json:"events"`
		Summary auditlog.Summary `json:"summary"`
	}{Events: events, Summary: auditlog.Summarize(events)})
}

// loopbackOnly rejects requests whose Host is not a loopback name, defeating
// DNS-rebinding attempts from a page in the user's browser.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		switch host {
		case "localhost", "127.0.0.1", "::1":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "assay dashboard accepts loopback requests only", http.StatusForbidden)
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
