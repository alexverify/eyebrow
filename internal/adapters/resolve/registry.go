package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/registry"
)

// maxRegistryBody caps how much of a registry response is read. A catalog is
// metadata; anything larger is a malformed or hostile endpoint.
const maxRegistryBody = 4 << 20 // 4 MiB

// Registry resolves a remote catalog entry (an app store listing).
//
// Unlike npm or git, there is nothing to download: the listing points at a
// hosted application whose code the registry never exposes. The integrity
// anchor is therefore twofold — the canonical digest of the published manifest,
// and the TLS SPKI pin of the distribution host. Together they detect a silent
// manifest edit or a swapped backing deployment, which is the most that can be
// established without the bytes.
//
// Schema coverage: this resolver reads the AgentOS `agentos.app.v1` record
// shape — a manifest object carrying entrypoint, permissions, requiredSecrets,
// commands and distribution.webUrl. It is named for the generic SourceRegistry
// kind because the *anchoring strategy* generalizes, but the field mapping does
// not. A record it cannot read is rejected outright rather than partially
// parsed: guessing would emit an anchor that pins nothing and findings drawn
// from fields that were never present. Supporting a second registry means
// adding a mapper here, not relying on the current one to cope.
type Registry struct {
	Client  *http.Client
	Fetcher CertFetcher
}

// NewRegistry builds a Registry resolver with the real TLS fetcher.
func NewRegistry() Registry {
	return Registry{Client: http.DefaultClient, Fetcher: TLSCertFetcher{}}
}

// NewRegistryWith builds a Registry resolver whose HTTP fetch and TLS probe
// both dial through dialCtx. A nil dialCtx behaves exactly like NewRegistry.
// Use it to enforce a destination policy on the registry fetch itself, in
// addition to the distribution host's TLS probe.
func NewRegistryWith(dialCtx func(ctx context.Context, network, address string) (net.Conn, error)) Registry {
	return Registry{
		Client:  httpClientFor(dialCtx),
		Fetcher: TLSCertFetcher{DialContext: dialCtx},
	}
}

// httpClientFor builds an *http.Client whose transport dials through dialCtx,
// or http.DefaultClient when dialCtx is nil.
func httpClientFor(dialCtx func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	if dialCtx == nil {
		return http.DefaultClient
	}
	// Clone the default transport so proxies from the environment and the
	// handshake and idle timeouts stay as they are; only the dial changes.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = dialCtx
	return &http.Client{Transport: t}
}

// Resolve satisfies ports.Resolver. Source.Ref is the app record URL.
func (r Registry) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	rec, err := r.fetchRecord(ctx, src.Ref)
	if err != nil {
		return ports.Resolution{}, err
	}

	// Refuse records this resolver cannot read. Without a manifest there is
	// nothing to anchor: canonicalizing the absent value would digest "null",
	// which is identical for every unrecognized registry, so verify could never
	// observe drift — and the listing rules would report confidently on fields
	// they never parsed. A hard failure becomes RESOLVE-FAILED upstream, which
	// is the honest outcome: integrity could not be established.
	manifest, ok := rec["manifest"].(map[string]any)
	if !ok {
		return ports.Resolution{}, fmt.Errorf("registry %s: no recognizable manifest in record; this resolver reads the AgentOS agentos.app.v1 shape", src.Ref)
	}
	canon, err := canonicalJSON(manifest)
	if err != nil {
		return ports.Resolution{}, fmt.Errorf("canonicalize manifest: %w", err)
	}

	warnings := []finding.Finding{{
		RuleID: "REGISTRY-METADATA-ONLY", Severity: finding.SeverityMedium, OWASP: "ASK-02",
		Explanation: "registry listing: the application's code was never obtained, so only the published manifest and its distribution host are pinned",
	}}
	warnings = append(warnings, registry.Assess(toListing(rec, manifest))...)

	res := ports.Resolution{
		PinnedRef:   src.Ref,
		ContentHash: digest.Inline(canon),
	}

	if webURL := distributionURL(manifest); webURL != "" {
		pin, err := r.Fetcher.SPKIPin(ctx, webURL)
		if err != nil {
			warnings = append(warnings, finding.Finding{
				RuleID: "TLS-PIN-FAILED", Severity: finding.SeverityHigh, OWASP: "ASK-02",
				Explanation: "could not obtain a TLS certificate pin for the distribution host: " + err.Error(),
			})
		} else {
			res.CertSPKI = pin
		}
	}

	res.Warnings = warnings
	return res, nil
}

// fetchRecord GETs an app record. Registries wrap the record under an "app"
// key; a bare object is accepted too, so one resolver serves both shapes.
func (r Registry) fetchRecord(ctx context.Context, url string) (map[string]any, error) {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBody))
	if err != nil {
		return nil, err
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("registry %s: %w", url, err)
	}
	if app, ok := envelope["app"].(map[string]any); ok {
		return app, nil
	}
	return envelope, nil
}

// canonicalJSON re-encodes a value with sorted keys and no incidental
// whitespace, so the digest depends on the manifest's content rather than on
// how the registry happened to serialize it.
func canonicalJSON(v any) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	return json.Marshal(v)
}
