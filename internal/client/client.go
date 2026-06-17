package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexverify/assay/internal/controlplane"
	"github.com/alexverify/assay/internal/domain/alert"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/policy"
)

// Client talks to a control-plane server. A zero base disables it; callers
// should check Configured before use and treat any method error as a signal to
// fall back to the local, offline path.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for a server base URL (e.g. https://assay.acme.internal)
// and a machine token. A trailing slash on base is trimmed.
func New(base, token string) *Client {
	return &Client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Configured reports whether a server is set. When false, the CLI stays fully
// local and never calls the network.
func (c *Client) Configured() bool { return c.base != "" }

// Submit sends this machine's content-free snapshot to the org's fleet.
func (c *Client) Submit(ctx context.Context, snap fleet.Snapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	req, err := c.request(ctx, http.MethodPost, "/v1/snapshots", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expect(resp, http.StatusNoContent)
}

// Fleet reads the org's aggregated blast-radius report.
func (c *Client) Fleet(ctx context.Context) (fleet.Report, error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/fleet", nil)
	if err != nil {
		return fleet.Report{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fleet.Report{}, err
	}
	defer resp.Body.Close()
	if err := expect(resp, http.StatusOK); err != nil {
		return fleet.Report{}, err
	}
	var rep fleet.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return fleet.Report{}, err
	}
	return rep, nil
}

// IngestAudit uploads a batch of local audit events to the org's log. The
// events are content-free by construction (arguments digested, secrets redacted
// at the shim). An empty batch is a no-op.
func (c *Client) IngestAudit(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	req, err := c.request(ctx, http.MethodPost, "/v1/audit", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expect(resp, http.StatusNoContent)
}

// Alerts reads the org's derived team alerts (drift, quarantine, blocked egress,
// denied tool calls).
func (c *Client) Alerts(ctx context.Context) ([]alert.Alert, error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/alerts", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expect(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var alerts []alert.Alert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, err
	}
	return alerts, nil
}

// Gate runs the fleet CI gate server-side over the org's submitted snapshots and
// returns the result. The caller maps !OK to a non-zero exit.
func (c *Client) Gate(ctx context.Context) (fleet.GateResult, error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/gate", nil)
	if err != nil {
		return fleet.GateResult{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fleet.GateResult{}, err
	}
	defer resp.Body.Close()
	if err := expect(resp, http.StatusOK); err != nil {
		return fleet.GateResult{}, err
	}
	var res fleet.GateResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fleet.GateResult{}, err
	}
	return res, nil
}

// Policy pulls the org's configured policy. ok is false when the server has no
// policy for the org (HTTP 404) — the caller then keeps its local policy.
func (c *Client) Policy(ctx context.Context) (pol policy.Policy, ok bool, err error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/policy", nil)
	if err != nil {
		return policy.Policy{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return policy.Policy{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return policy.Policy{}, false, nil
	}
	if err := expect(resp, http.StatusOK); err != nil {
		return policy.Policy{}, false, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&pol); err != nil {
		return policy.Policy{}, false, err
	}
	return pol, true, nil
}

// TrustedKeys pulls the org's trusted signing keys (possibly empty).
func (c *Client) TrustedKeys(ctx context.Context) ([]controlplane.TrustedKey, error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/registry/keys", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expect(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var keys []controlplane.TrustedKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// Health checks the server is reachable and serving.
func (c *Client) Health(ctx context.Context) error {
	req, err := c.request(ctx, http.MethodGet, "/v1/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expect(resp, http.StatusOK)
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// expect returns an error unless the response carries the wanted status,
// folding a short body snippet into the message for diagnosis.
func expect(resp *http.Response, want int) error {
	if resp.StatusCode == want {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return fmt.Errorf("control plane: %s %s → %s: %s",
		resp.Request.Method, resp.Request.URL.Path, resp.Status, strings.TrimSpace(string(snippet)))
}
