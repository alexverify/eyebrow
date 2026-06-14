package dashboard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/adapters/auditlog"
	"github.com/alexverify/agentguard/internal/dashboard"
	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

func testServer(t *testing.T) *dashboard.Server {
	t.Helper()
	current := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "github", ContentHash: "sha256-new",
			Findings: []finding.Finding{{RuleID: "RCE-PIPE-EXEC", Severity: finding.SeverityCritical}}},
	}, time.Unix(0, 0).UTC(), "agentguard/test")
	locked := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "github", ContentHash: "sha256-old"},
	}, time.Unix(0, 0).UTC(), "agentguard/test")

	return dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return current, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return locked, nil },
		Audit: func(auditlog.Filter) ([]audit.Event, error) {
			return []audit.Event{
				{Server: "github", Kind: audit.KindToolCall, Tool: "create_issue", Status: audit.StatusOK},
				{Server: "github", Kind: audit.KindToolCall, Tool: "delete_repo", Status: audit.StatusDenied},
			}, nil
		},
	})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7113"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestInventoryEndpoint(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/api/inventory")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var lf lockfile.Lockfile
	if err := json.Unmarshal(rec.Body.Bytes(), &lf); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(lf.Artifacts) != 1 || lf.Artifacts[0].Name != "github" {
		t.Errorf("inventory = %+v", lf.Artifacts)
	}
}

func TestDriftEndpoint(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/api/drift")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var diff lockfile.Diff
	json.Unmarshal(rec.Body.Bytes(), &diff)
	// content hash moved old→new
	found := false
	for _, c := range diff.Changes {
		if c.Kind == lockfile.DriftContentChanged && c.ID == "a1" {
			found = true
		}
	}
	if !found {
		t.Errorf("drift should report the content change: %+v", diff.Changes)
	}
}

func TestAuditEndpointAndFilter(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/api/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Events  []audit.Event    `json:"events"`
		Summary auditlog.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("events = %d, want 2", len(resp.Events))
	}
	if resp.Summary.Denied != 1 {
		t.Errorf("summary denied = %d, want 1", resp.Summary.Denied)
	}
}

func TestScanEndpointAssemblesDashboardShape(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/api/scan")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Artifacts []dashboard.DashArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.Artifacts) != 1 {
		t.Fatalf("got %d artifacts, want 1", len(resp.Artifacts))
	}
	a := resp.Artifacts[0]
	if a.Name != "github" || a.Kind != "mcp" || a.Agent != "Claude Code" {
		t.Errorf("artifact mapping: %+v", a)
	}
	// current (sha256-new) vs locked (sha256-old) → drifted
	if a.Drift != "drifted" {
		t.Errorf("drift = %q, want drifted", a.Drift)
	}
	if len(a.Findings) != 1 || a.Findings[0].Pattern != "remote-code-exec" {
		t.Errorf("findings = %+v", a.Findings)
	}
}

func TestServesStaticIndex(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct[:9] != "text/html" {
		t.Errorf("index content-type = %q", ct)
	}
}

// TestRejectsNonLoopbackHost guards against DNS-rebinding: a browser tricked
// into resolving an attacker domain to 127.0.0.1 would carry that Host header.
func TestRejectsNonLoopbackHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7113/api/inventory", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host must be rejected, got %d", rec.Code)
	}
}

func TestWriteEndpointTokenGuard(t *testing.T) {
	lf := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "github"},
	}, time.Unix(0, 0).UTC(), "t")
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		Mutate: func(ctx context.Context, fn func(*lockfile.Lockfile) error) error {
			return fn(&lf)
		},
	})
	h := srv.Handler()

	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7113/api/quarantine",
			strings.NewReader(`{"id":"a1","on":true}`))
		if token != "" {
			req.Header.Set("X-Agentguard-Token", token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Without the token, the write is forbidden.
	if rec := post(""); rec.Code != http.StatusForbidden {
		t.Fatalf("missing token → 403, got %d", rec.Code)
	}
	if lf.Artifacts[0].Quarantined {
		t.Fatal("artifact must not be mutated by a tokenless request")
	}

	// With the token, the write succeeds and persists.
	if rec := post(srv.Token()); rec.Code != http.StatusOK {
		t.Fatalf("with token → 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !lf.Artifacts[0].Quarantined {
		t.Fatal("artifact should be quarantined after an authorized write")
	}
}

func TestWriteEndpointReadOnlyWhenNoMutate(t *testing.T) {
	srv := testServer(t) // no Mutate dep
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7113/api/freeze",
		strings.NewReader(`{"id":"a1","on":true}`))
	req.Header.Set("X-Agentguard-Token", srv.Token())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only server should refuse writes with 403, got %d", rec.Code)
	}
}

func TestTokenEndpoint(t *testing.T) {
	srv := testServer(t)
	rec := get(t, srv.Handler(), "/api/token")
	var body struct {
		Token    string `json:"token"`
		Writable bool   `json:"writable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token != srv.Token() || body.Token == "" {
		t.Fatalf("token endpoint = %q, want %q", body.Token, srv.Token())
	}
	if body.Writable {
		t.Errorf("read-only server should report writable=false")
	}
}
