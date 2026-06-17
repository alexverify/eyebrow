package client_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/assay/internal/client"
	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/alert"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
	"github.com/alexverify/assay/internal/domain/reputation"
)

// liveServer spins up the real control-plane handler so the client is tested
// against the actual server, end to end.
func liveServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	svc := controlplane.NewService(controlplane.NewMemStore(), nil)
	srv := httptest.NewServer(controlplane.NewServer(svc, controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)
	return srv, "tok"
}

func TestClientSubmitThenFleet(t *testing.T) {
	srv, tok := liveServer(t)
	c := client.New(srv.URL, tok)
	ctx := context.Background()

	if err := c.Submit(ctx, fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "x", Name: "feed", Kind: "skill", Hash: "h1", Drift: "drifted", Verdict: "review"},
	}}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	rep, err := c.Fleet(ctx)
	if err != nil {
		t.Fatalf("fleet: %v", err)
	}
	if rep.Owners != 1 || len(rep.Exposures) != 1 || rep.Exposures[0].Name != "feed" {
		t.Errorf("report = %+v", rep)
	}
}

func TestClientBadTokenErrors(t *testing.T) {
	srv, _ := liveServer(t)
	c := client.New(srv.URL, "wrong")
	if _, err := c.Fleet(context.Background()); err == nil {
		t.Error("a bad token should surface an error the caller can fall back from")
	}
}

func TestConfigured(t *testing.T) {
	if client.New("", "").Configured() {
		t.Error("an empty base must report not configured (stay local)")
	}
	if !client.New("https://x", "t").Configured() {
		t.Error("a set base should report configured")
	}
}

func TestHealth(t *testing.T) {
	srv, tok := liveServer(t)
	if err := client.New(srv.URL, tok).Health(context.Background()); err != nil {
		t.Errorf("health: %v", err)
	}
}

func TestClientPullsPolicyAndKeys(t *testing.T) {
	cfg := controlplane.NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{RequireApproval: true, Fleet: policy.FleetPolicy{MaxBlastRadius: 4}})
	cfg.SetTrustedKeys("acme", []controlplane.TrustedKey{{Key: "AAAA==", Name: "alice"}})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(controlplane.NewMemStore(), cfg),
		controlplane.StaticAuth{"tok": "acme"},
	))
	t.Cleanup(srv.Close)
	c := client.New(srv.URL, "tok")

	p, ok, err := c.Policy(context.Background())
	if err != nil || !ok {
		t.Fatalf("policy pull: ok=%v err=%v", ok, err)
	}
	if !p.RequireApproval || p.Fleet.MaxBlastRadius != 4 {
		t.Errorf("policy = %+v", p)
	}
	keys, err := c.TrustedKeys(context.Background())
	if err != nil || len(keys) != 1 || keys[0].Name != "alice" {
		t.Errorf("keys = %+v, err=%v", keys, err)
	}
}

func TestClientIngestAuditThenAlerts(t *testing.T) {
	store := controlplane.NewMemStore()
	store.PutSnapshot("acme", fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "x", Name: "feed", Hash: "h", Drift: "drifted", Verdict: "review"}}})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(store, nil), controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)
	c := client.New(srv.URL, "tok")
	ctx := context.Background()

	if err := c.IngestAudit(ctx, []audit.Event{
		{Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	alerts, err := c.Alerts(ctx)
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	var kinds []alert.Kind
	for _, a := range alerts {
		kinds = append(kinds, a.Kind)
	}
	if len(alerts) < 2 {
		t.Errorf("expected drift + egress alerts, got %+v", kinds)
	}
}

func TestClientConformance(t *testing.T) {
	cfg := controlplane.NewMemConfig()
	cfg.SetPolicy("acme", policy.Policy{BlockPublishers: []string{"evil.example"}})
	store := controlplane.NewMemStore()
	store.PutSnapshot("acme", fleet.Snapshot{Owner: "bob", Artifacts: []fleet.Artifact{
		{ID: "bad", Name: "feed", Source: "evil.example/f", Drift: "verified", Verdict: "trusted"}}})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(store, cfg), controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)

	con, err := client.New(srv.URL, "tok").Conformance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if con.Owners != 1 || con.Compliant != 0 {
		t.Errorf("conformance = %+v", con)
	}
}

func TestClientReputationLookup(t *testing.T) {
	cfg := controlplane.NewMemConfig()
	cfg.SetReputation("acme", reputation.Source{
		"sha256-aaa": {Hash: "sha256-aaa", Trusters: 11},
	})
	srv := httptest.NewServer(controlplane.NewServer(
		controlplane.NewService(controlplane.NewMemStore(), cfg), controlplane.StaticAuth{"tok": "acme"}))
	t.Cleanup(srv.Close)

	src, err := client.New(srv.URL, "tok").Reputation(context.Background(), []string{"sha256-aaa", "sha256-miss"})
	if err != nil {
		t.Fatal(err)
	}
	if sig, ok := src.Lookup("sha256-aaa"); !ok || sig.Trusters != 11 {
		t.Errorf("aaa = %+v ok=%v", sig, ok)
	}
	if _, ok := src.Lookup("sha256-miss"); ok {
		t.Error("a miss must not resolve")
	}
}

func TestClientPolicyNotConfiguredFallsBack(t *testing.T) {
	// Server with no config → 404 → ok=false, no error (caller stays local).
	srv, tok := liveServer(t)
	_, ok, err := client.New(srv.URL, tok).Policy(context.Background())
	if err != nil {
		t.Fatalf("a missing policy must not error: %v", err)
	}
	if ok {
		t.Error("unconfigured policy should report ok=false")
	}
}
