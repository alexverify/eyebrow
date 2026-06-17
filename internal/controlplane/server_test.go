package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/assay/internal/domain/fleet"
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
