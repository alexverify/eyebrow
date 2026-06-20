package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/alert"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

func testHandler() http.Handler {
	svc := NewService(NewMemStore(), nil)
	return NewServer(svc, StaticAuth{"tok-acme": "acme", "tok-globex": "globex"})
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSubmitAndFleetRoundTrip(t *testing.T) {
	h := testHandler()
	snap := fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "x", Name: "feed", Kind: "skill", Hash: "h1", Drift: "drifted", Verdict: "review"},
	}}
	if rec := do(t, h, "POST", "/v1/snapshots", "tok-acme", snap); rec.Code != http.StatusNoContent {
		t.Fatalf("submit = %d, body=%s", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/v1/fleet", "tok-acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet = %d", rec.Code)
	}
	var rep fleet.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Owners != 1 || len(rep.Exposures) != 1 || rep.Exposures[0].Name != "feed" {
		t.Errorf("report = %+v", rep)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	h := testHandler()
	if rec := do(t, h, "GET", "/v1/fleet", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/fleet", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token = %d, want 401", rec.Code)
	}
}

func TestTokenScopesOrgIsolation(t *testing.T) {
	h := testHandler()
	do(t, h, "POST", "/v1/snapshots", "tok-acme", fleet.Snapshot{Owner: "alice",
		Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Hash: "h"}}})
	// globex's token must not see acme's fleet.
	rec := do(t, h, "GET", "/v1/fleet", "tok-globex", nil)
	var rep fleet.Report
	json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Owners != 0 {
		t.Errorf("globex leaked acme data: %+v", rep)
	}
}

func TestSubmitRejectsBadJSON(t *testing.T) {
	h := testHandler()
	req := httptest.NewRequest("POST", "/v1/snapshots", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Authorization", "Bearer tok-acme")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad json = %d, want 400", rec.Code)
	}
}

func TestSubmitRejectsOwnerlessSnapshot(t *testing.T) {
	h := testHandler()
	rec := do(t, h, "POST", "/v1/snapshots", "tok-acme", fleet.Snapshot{Owner: ""})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ownerless snapshot = %d, want 400", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := testHandler()
	if rec := do(t, h, "GET", "/v1/healthz", "", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}
}

func TestPolicyServedWhenConfigured(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{RequireApproval: true, Fleet: policy.FleetPolicy{MaxBlastRadius: 2}})
	cfg.SetTrustedKeys("acme", []TrustedKey{{Key: "AAAA==", Name: "alice"}})
	h := NewServer(NewService(NewMemStore(), cfg), StaticAuth{"tok-acme": "acme", "tok-globex": "globex"})

	rec := do(t, h, "GET", "/v1/policy", "tok-acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy = %d", rec.Code)
	}
	var p policy.Policy
	json.Unmarshal(rec.Body.Bytes(), &p)
	if !p.RequireApproval || p.Fleet.MaxBlastRadius != 2 {
		t.Errorf("policy = %+v", p)
	}

	// An org with no configured policy → 404 (CLI falls back to local).
	if rec := do(t, h, "GET", "/v1/policy", "tok-globex", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unconfigured org policy = %d, want 404", rec.Code)
	}

	rec = do(t, h, "GET", "/v1/registry/keys", "tok-acme", nil)
	var keys []TrustedKey
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 1 || keys[0].Name != "alice" {
		t.Errorf("keys = %+v", keys)
	}
}

func TestGateEndpoint(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{Fleet: policy.FleetPolicy{MaxBlastRadius: 1}})
	h := NewServer(NewService(seededStore(), cfg), StaticAuth{"tok-acme": "acme"})
	rec := do(t, h, "GET", "/v1/gate", "tok-acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gate = %d", rec.Code)
	}
	var res fleet.GateResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.OK || len(res.BlastBreaches) != 1 {
		t.Errorf("gate result = %+v", res)
	}
}

func TestConformanceEndpoint(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{BlockPublishers: []string{"evil.example"}})
	store := NewMemStore()
	store.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "ok", Name: "linter", Source: "github.com/x", Drift: "verified", Verdict: "trusted"}}})
	store.PutSnapshot("acme", fleet.Snapshot{Owner: "bob", Artifacts: []fleet.Artifact{
		{ID: "bad", Name: "feed", Source: "evil.example/f", Drift: "verified", Verdict: "trusted"}}})
	h := NewServer(NewService(store, cfg), StaticAuth{"tok-acme": "acme"})

	rec := do(t, h, "GET", "/v1/conformance", "tok-acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("conformance = %d", rec.Code)
	}
	var con fleet.Conformance
	json.Unmarshal(rec.Body.Bytes(), &con)
	if con.Owners != 2 || con.Compliant != 1 {
		t.Errorf("conformance = %+v", con)
	}
}

func TestAuditIngestThenAlerts(t *testing.T) {
	h := NewServer(NewService(seededStore(), nil), StaticAuth{"tok-acme": "acme"})
	// Ingest a denied egress event.
	ev := []audit.Event{{Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied}}
	if rec := do(t, h, "POST", "/v1/audit", "tok-acme", ev); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest = %d", rec.Code)
	}
	rec := do(t, h, "GET", "/v1/alerts", "tok-acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts = %d", rec.Code)
	}
	var alerts []alert.Alert
	json.Unmarshal(rec.Body.Bytes(), &alerts)
	// seededStore has a 2-machine drift → a drift alert; plus the egress alert.
	var sawDrift, sawEgress bool
	for _, a := range alerts {
		switch a.Kind {
		case alert.KindDrift:
			sawDrift = true
		case alert.KindEgressDenied:
			sawEgress = true
		}
	}
	if !sawDrift || !sawEgress {
		t.Errorf("expected drift + egress alerts, got %+v", alerts)
	}
}

func TestAuditAndAlertsRequireAuth(t *testing.T) {
	h := testHandler()
	if rec := do(t, h, "POST", "/v1/audit", "", []audit.Event{{Kind: audit.KindToolCall}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("ingest without token = %d, want 401", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/alerts", "bad", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("alerts with bad token = %d, want 401", rec.Code)
	}
}

// seededStore returns a store with a two-machine drift on the "acme" org.
func seededStore() *MemStore {
	s := NewMemStore()
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Hash: "h1", Drift: "drifted", Verdict: "review"}}})
	s.PutSnapshot("acme", fleet.Snapshot{Owner: "bob", Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Hash: "h2", Drift: "drifted", Verdict: "review"}}})
	return s
}

func TestPolicyAndKeysRequireAuth(t *testing.T) {
	h := testHandler()
	if rec := do(t, h, "GET", "/v1/policy", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("policy without token = %d, want 401", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/registry/keys", "bad", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("keys with bad token = %d, want 401", rec.Code)
	}
}
