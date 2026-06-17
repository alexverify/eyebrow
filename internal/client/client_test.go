package client_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/assay/internal/client"
	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/fleet"
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
