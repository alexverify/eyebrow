package dashboard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/assay/internal/adapters/auditlog"
	"github.com/alexverify/assay/internal/dashboard"
	"github.com/alexverify/assay/internal/domain/alert"
	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/policy"
	"github.com/alexverify/assay/internal/domain/posture"
	"github.com/alexverify/assay/internal/domain/reputation"
)

func testServer(t *testing.T) *dashboard.Server {
	t.Helper()
	current := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "github", ContentHash: "sha256-new",
			Findings: []finding.Finding{{RuleID: "RCE-PIPE-EXEC", Severity: finding.SeverityCritical}}},
	}, time.Unix(0, 0).UTC(), "assay/test")
	locked := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "github", ContentHash: "sha256-old"},
	}, time.Unix(0, 0).UTC(), "assay/test")

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

func TestFleetEndpoint(t *testing.T) {
	srv := dashboard.New(dashboard.Deps{
		Fleet: func(context.Context) (fleet.Report, error) {
			return fleet.Aggregate([]fleet.Snapshot{
				{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Kind: "skill", Hash: "h1", Drift: "drifted", Verdict: "quarantine"}}},
				{Owner: "bob", Artifacts: []fleet.Artifact{{ID: "x", Name: "feed", Kind: "skill", Hash: "h2", Drift: "verified", Verdict: "trusted"}}},
			}), nil
		},
	})
	rec := get(t, srv.Handler(), "/api/fleet")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var rep fleet.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if rep.Owners != 2 || len(rep.Exposures) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if e := rep.Exposures[0]; e.Installs != 2 || e.Drifted != 1 || e.Variants != 2 {
		t.Errorf("blast radius = %+v", e)
	}
	// The same endpoint also carries the heatmap (G2).
	if len(rep.Grid.Rows) != 1 || len(rep.Grid.Owners) != 2 {
		t.Errorf("grid = %+v", rep.Grid)
	}
}

func TestFleetEndpointCarriesConformance(t *testing.T) {
	srv := dashboard.New(dashboard.Deps{
		Conformance: func(context.Context) (fleet.Conformance, error) {
			return fleet.CheckConformance(
				policy.Policy{BlockPublishers: []string{"evil.example"}},
				[]fleet.Snapshot{
					{Owner: "alice", Artifacts: []fleet.Artifact{{ID: "ok", Name: "linter", Source: "github.com/x", Drift: "verified", Verdict: "trusted"}}},
					{Owner: "bob", Artifacts: []fleet.Artifact{{ID: "bad", Name: "feed", Source: "evil.example/f", Drift: "verified", Verdict: "trusted"}}},
				}), nil
		},
	})
	rec := get(t, srv.Handler(), "/api/fleet")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Conformance fleet.Conformance `json:"conformance"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if resp.Conformance.Owners != 2 || resp.Conformance.Compliant != 1 {
		t.Errorf("conformance = %+v", resp.Conformance)
	}
}

func TestAlertsEndpoint(t *testing.T) {
	srv := dashboard.New(dashboard.Deps{
		Alerts: func(context.Context) ([]alert.Alert, error) {
			return []alert.Alert{
				{Kind: alert.KindEgressDenied, Severity: alert.SeverityHigh, Subject: "evil.example", Detail: "blocked 2x", Count: 2},
			}, nil
		},
	})
	rec := get(t, srv.Handler(), "/api/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Alerts []alert.Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Alerts) != 1 || resp.Alerts[0].Subject != "evil.example" {
		t.Errorf("alerts = %+v", resp.Alerts)
	}
}

func TestAlertsEndpointEmptyWhenUnset(t *testing.T) {
	rec := get(t, testServer(t).Handler(), "/api/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Alerts []alert.Alert `json:"alerts"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Alerts) != 0 {
		t.Errorf("no Alerts dep should yield an empty list, got %+v", resp.Alerts)
	}
}

func TestFleetEndpointEmptyWhenUnset(t *testing.T) {
	// No Fleet dep → an empty report, never an error.
	rec := get(t, testServer(t).Handler(), "/api/fleet")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var rep fleet.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if rep.Owners != 0 || len(rep.Exposures) != 0 {
		t.Errorf("unset fleet should be empty, got %+v", rep)
	}
}

func TestActivationSurfacesUsageForNonMCP(t *testing.T) {
	// A skill has no MCP shim, so its only usage signal is the hook-fed
	// activation event. The scan view must show it used (F1b) just like a
	// wrapped server's tool calls.
	skill := lockfile.Build([]artifact.Artifact{
		{ID: "s1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "pdf-skill", ContentHash: "h"},
	}, time.Unix(0, 0).UTC(), "assay/test")
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return skill, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return skill, nil },
		Audit: func(auditlog.Filter) ([]audit.Event, error) {
			return []audit.Event{
				{Server: "pdf-skill", Kind: audit.KindActivation, Tool: "skill", At: time.Unix(1000, 0).UTC()},
				{Server: "pdf-skill", Kind: audit.KindActivation, Tool: "skill", At: time.Unix(2000, 0).UTC()},
			}, nil
		},
	})
	rec := get(t, srv.Handler(), "/api/scan")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Artifacts []struct {
			Name  string `json:"name"`
			Usage *struct {
				Count int `json:"count"`
			} `json:"usage"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.Artifacts) != 1 {
		t.Fatalf("got %d artifacts", len(resp.Artifacts))
	}
	if resp.Artifacts[0].Usage == nil || resp.Artifacts[0].Usage.Count != 2 {
		t.Errorf("skill usage not surfaced from activations: %+v", resp.Artifacts[0].Usage)
	}
}

func TestScanServesLineDiffsFromBlobs(t *testing.T) {
	// One artifact whose file content drifted: locked hash h-old, current h-new,
	// with a single file that gained a malicious line. The blob store holds both
	// versions, so the scan view should carry the literal +/- lines (H1b).
	locked := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "feed", ContentHash: "h-old",
			Files: []artifact.FileRef{{Path: "run.py", Hash: "f-old"}}},
	}, time.Unix(0, 0).UTC(), "assay/test")
	current := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "feed", ContentHash: "h-new",
			Files: []artifact.FileRef{{Path: "run.py", Hash: "f-new"}}},
	}, time.Unix(0, 0).UTC(), "assay/test")

	blobs := map[string]map[string][]byte{
		"h-old": {"run.py": []byte("print('hi')\n")},
		"h-new": {"run.py": []byte("print('hi')\nexfiltrate(wallet)\n")},
	}
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return current, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return locked, nil },
		Blobs: func(h string) (map[string][]byte, error) {
			return blobs[h], nil
		},
	})
	rec := get(t, srv.Handler(), "/api/scan")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "exfiltrate(wallet)") {
		t.Errorf("line diff should carry the added malicious line:\n%s", rec.Body.String())
	}
	var resp struct {
		Artifacts []struct {
			LineDiffs []struct {
				Path  string `json:"path"`
				Added int    `json:"added"`
			} `json:"lineDiffs"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Artifacts) != 1 || len(resp.Artifacts[0].LineDiffs) != 1 {
		t.Fatalf("expected one file line diff, got %+v", resp.Artifacts)
	}
	if d := resp.Artifacts[0].LineDiffs[0]; d.Path != "run.py" || d.Added != 1 {
		t.Errorf("line diff = %+v, want run.py +1", d)
	}
}

func TestScanDegradesWithoutBlobs(t *testing.T) {
	// No Blobs dep → no line diffs, but the scan view still renders (file-name
	// list remains the honest floor).
	rec := get(t, testServer(t).Handler(), "/api/scan")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "lineDiffs") {
		t.Errorf("without a blob store there should be no lineDiffs field:\n%s", rec.Body.String())
	}
}

func TestScanSurfacesReputationForInventoryHashes(t *testing.T) {
	// The Reputation dep is queried with the inventory's content hashes (the H3b
	// live-lookup seam); its result must surface on the matching artifact.
	inv := lockfile.Build([]artifact.Artifact{
		{ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "feed", ContentHash: "sha256-aaa"},
	}, time.Unix(0, 0).UTC(), "assay/test")
	var gotHashes []string
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return inv, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return inv, nil },
		Reputation: func(hashes []string) (reputation.Source, error) {
			gotHashes = hashes
			return reputation.Source{"sha256-aaa": {Hash: "sha256-aaa", Trusters: 11}}, nil
		},
	})
	rec := get(t, srv.Handler(), "/api/scan")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(gotHashes) != 1 || gotHashes[0] != "sha256-aaa" {
		t.Errorf("reputation dep should be queried with inventory hashes, got %v", gotHashes)
	}
	if !strings.Contains(rec.Body.String(), "\"trusters\":11") {
		t.Errorf("reputation should surface on the artifact:\n%s", rec.Body.String())
	}
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
			req.Header.Set("X-Assay-Token", token)
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
	req.Header.Set("X-Assay-Token", srv.Token())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only server should refuse writes with 403, got %d", rec.Code)
	}
}

// policyServer wires a server backed by an in-memory policy with both reads and
// writes enabled, returning the server and a pointer to the live policy.
func policyServer(t *testing.T) (*dashboard.Server, *policy.Policy) {
	t.Helper()
	p := policy.Default()
	lf := lockfile.Build(nil, time.Unix(0, 0).UTC(), "t")
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		Policy:    func(context.Context) (policy.Policy, error) { return p, nil },
		MutatePolicy: func(ctx context.Context, fn func(*policy.Policy) error) error {
			return fn(&p)
		},
	})
	return srv, &p
}

func postJSON(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7113"+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Assay-Token", token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPolicyEditorReadAndWrite(t *testing.T) {
	srv, p := policyServer(t)
	h := srv.Handler()

	// GET returns the current policy.
	rec := get(t, h, "/api/policy")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/policy = %d", rec.Code)
	}

	// A tokenless POST is refused and does not mutate.
	if rec := postJSON(t, h, "/api/policy", "", `{"blockPublishers":["giftshop.club"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("tokenless policy write → 403, got %d", rec.Code)
	}
	if len(p.BlockPublishers) != 0 {
		t.Fatal("policy must not change on a tokenless write")
	}

	// An authorized POST replaces the lists.
	body := `{"allowPublishers":["github.com/myorg"],"blockPublishers":["giftshop.club"," "],"blockArtifacts":["evil"]}`
	if rec := postJSON(t, h, "/api/policy", srv.Token(), body); rec.Code != http.StatusOK {
		t.Fatalf("authorized policy write → 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(p.BlockPublishers) != 1 || p.BlockPublishers[0] != "giftshop.club" {
		t.Errorf("blockPublishers not saved (blanks should drop): %+v", p.BlockPublishers)
	}
	if len(p.AllowPublishers) != 1 || len(p.BlockArtifacts) != 1 {
		t.Errorf("allow/block lists not saved: %+v", *p)
	}
}

func TestMuteEndpointAppendsRationale(t *testing.T) {
	srv, p := policyServer(t)
	h := srv.Handler()

	if rec := postJSON(t, h, "/api/mute", srv.Token(), `{"rule":"EXEC-PRIMITIVE","reason":"build step","by":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("mute → 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(p.Mutes) != 1 || p.Mutes[0].Rule != "EXEC-PRIMITIVE" || p.Mutes[0].Reason != "build step" || p.Mutes[0].By != "alice" {
		t.Fatalf("mute not recorded with rationale: %+v", p.Mutes)
	}
	// Muting the same rule again is idempotent.
	postJSON(t, h, "/api/mute", srv.Token(), `{"rule":"EXEC-PRIMITIVE","reason":"again"}`)
	if len(p.Mutes) != 1 {
		t.Errorf("re-muting should be idempotent, got %+v", p.Mutes)
	}
	// A mute without a rule is a bad request.
	if rec := postJSON(t, h, "/api/mute", srv.Token(), `{"reason":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("mute without a rule → 400, got %d", rec.Code)
	}
}

func TestEgressAllowAddsHostRule(t *testing.T) {
	srv, p := policyServer(t)
	h := srv.Handler()

	if rec := postJSON(t, h, "/api/egress-allow", srv.Token(), `{"server":"pdf","host":"cdn.pdf.dev"}`); rec.Code != http.StatusOK {
		t.Fatalf("egress-allow → 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	rule, ok := p.MCP.Servers["pdf"]
	if !ok || len(rule.AllowHosts) != 1 || rule.AllowHosts[0] != "cdn.pdf.dev" {
		t.Fatalf("host rule not written: %+v", p.MCP.Servers)
	}
	// The proxy's host decision now allows it.
	if !p.DecideHost("pdf", "cdn.pdf.dev").Allowed {
		t.Error("the newly allowed host should pass DecideHost")
	}
	// Idempotent re-add.
	postJSON(t, h, "/api/egress-allow", srv.Token(), `{"server":"pdf","host":"cdn.pdf.dev"}`)
	if len(p.MCP.Servers["pdf"].AllowHosts) != 1 {
		t.Errorf("re-allowing a host should be idempotent: %+v", p.MCP.Servers["pdf"].AllowHosts)
	}
}

func TestPolicyWriteReadOnlyWhenNoMutatePolicy(t *testing.T) {
	srv := testServer(t) // no MutatePolicy dep
	if rec := postJSON(t, srv.Handler(), "/api/mute", srv.Token(), `{"rule":"X"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only policy server should refuse writes with 403, got %d", rec.Code)
	}
}

func TestHistoryEndpoint(t *testing.T) {
	lf := lockfile.Build(nil, time.Unix(0, 0).UTC(), "t")
	srv := dashboard.New(dashboard.Deps{
		Inventory: func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		Locked:    func(context.Context) (lockfile.Lockfile, error) { return lf, nil },
		History: func(context.Context) ([]posture.Posture, error) {
			return []posture.Posture{{Total: 5, Trusted: 5}, {Total: 6, Trusted: 5, Review: 1}}, nil
		},
	})
	rec := get(t, srv.Handler(), "/api/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("history status = %d", rec.Code)
	}
	var resp struct {
		History []posture.Posture `json:"history"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.History) != 2 || resp.History[1].Review != 1 {
		t.Errorf("history payload = %+v", resp.History)
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
