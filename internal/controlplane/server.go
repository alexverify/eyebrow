package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/alexverify/eyebrow/internal/domain/alert"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

// maxBody caps a submission body. Snapshots are small (counts and hashes), so a
// generous-but-bounded limit guards against a malformed or hostile client.
const maxBody = 4 << 20 // 4 MiB

// NewServer returns the control-plane HTTP handler (slice 4a): submit a
// snapshot, read the aggregated fleet. Every route is authenticated by a
// machine bearer token that scopes the request to one org.
func NewServer(svc *Service, auth Auth) http.Handler {
	h := &handler{svc: svc, auth: auth}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/snapshots", h.submit)
	mux.HandleFunc("POST /v1/audit", h.ingestAudit)
	mux.HandleFunc("POST /v1/reputation", h.reputation)
	mux.HandleFunc("GET /v1/fleet", h.fleet)
	mux.HandleFunc("GET /v1/conformance", h.conformance)
	mux.HandleFunc("GET /v1/alerts", h.alerts)
	mux.HandleFunc("GET /v1/gate", h.gate)
	mux.HandleFunc("GET /v1/policy", h.policy)
	mux.HandleFunc("GET /v1/registry/keys", h.keys)
	mux.HandleFunc("GET /v1/healthz", h.health)
	return mux
}

type handler struct {
	svc  *Service
	auth Auth
}

// org authenticates the request, returning the scoped org. On failure it writes
// 401 and returns ok=false.
func (h *handler) org(w http.ResponseWriter, r *http.Request) (string, bool) {
	org, ok := h.auth.Org(bearerToken(r.Header.Get("Authorization")))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return org, true
}

func (h *handler) submit(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	var snap fleet.Snapshot
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&snap); err != nil {
		http.Error(w, "bad snapshot json", http.StatusBadRequest)
		return
	}
	if err := h.svc.Submit(org, snap); err != nil {
		if errors.Is(err, ErrInvalidSnapshot) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) ingestAudit(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	var events []audit.Event
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&events); err != nil {
		http.Error(w, "bad audit json", http.StatusBadRequest)
		return
	}
	if err := h.svc.IngestAudit(org, events); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) conformance(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	con, err := h.svc.Conformance(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, con)
}

func (h *handler) alerts(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	alerts, err := h.svc.Alerts(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []alert.Alert{}
	}
	writeJSON(w, alerts)
}

func (h *handler) fleet(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	rep, err := h.svc.Fleet(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}

func (h *handler) gate(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Gate(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

// reputation looks up a batch of content hashes in the org's corpus. The body
// is a JSON array of hashes — a lookup sends only hashes the caller already
// holds, and the response carries only matches.
func (h *handler) reputation(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	var hashes []string
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&hashes); err != nil {
		http.Error(w, "bad hashes json", http.StatusBadRequest)
		return
	}
	src, err := h.svc.Reputation(org, hashes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if src == nil {
		src = reputation.Source{}
	}
	writeJSON(w, src)
}

func (h *handler) policy(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	p, configured, err := h.svc.Policy(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !configured {
		// No org policy: 404 tells the CLI to keep its local policy.
		http.Error(w, "no policy configured", http.StatusNotFound)
		return
	}
	writeJSON(w, p)
}

func (h *handler) keys(w http.ResponseWriter, r *http.Request) {
	org, ok := h.org(w, r)
	if !ok {
		return
	}
	keys, err := h.svc.TrustedKeys(org)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []TrustedKey{}
	}
	writeJSON(w, keys)
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
