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
