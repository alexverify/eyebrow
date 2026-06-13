// Package dashboard serves a local, read-only web view of what agentguard sees
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
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/alexverify/agentguard/internal/adapters/auditlog"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
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
	// Static overrides the embedded UI assets (used in tests); nil uses the
	// embedded Next.js export.
	Static fs.FS
}

// Server renders the dashboard.
type Server struct {
	deps   Deps
	static fs.FS
}

// New constructs a Server.
func New(d Deps) *Server {
	static := d.Static
	if static == nil {
		sub, err := fs.Sub(assetsFS, "assets")
		if err == nil {
			static = sub
		}
	}
	return &Server{deps: d, static: static}
}

// Handler returns the HTTP handler: JSON under /api, the embedded UI elsewhere,
// all behind the loopback-Host guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/inventory", s.handleInventory)
	mux.HandleFunc("/api/drift", s.handleDrift)
	mux.HandleFunc("/api/audit", s.handleAudit)
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
			http.Error(w, "agentguard dashboard accepts loopback requests only", http.StatusForbidden)
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
