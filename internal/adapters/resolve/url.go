package resolve

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// CertFetcher returns the SPKI pin (base64 SHA-256 of the leaf certificate's
// SubjectPublicKeyInfo) for the host of a URL.
type CertFetcher interface {
	SPKIPin(ctx context.Context, rawURL string) (string, error)
}

// URL resolves remote (SSE/HTTP) MCP sources. Remote code cannot be hashed, so
// the integrity anchor is the TLS certificate's SPKI pin; any change is drift.
type URL struct {
	Fetcher CertFetcher
}

// NewURL builds a URL resolver with the real TLS fetcher.
func NewURL(f CertFetcher) URL { return URL{Fetcher: f} }

// Resolve satisfies ports.Resolver.
func (u URL) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	warnings := []finding.Finding{{
		RuleID: "REMOTE-UNHASHABLE", Severity: finding.SeverityMedium, OWASP: "ASK-02",
		Explanation: "remote MCP code cannot be hashed; pinning the TLS certificate (SPKI) instead",
	}}
	pin, err := u.Fetcher.SPKIPin(ctx, src.Ref)
	if err != nil {
		warnings = append(warnings, finding.Finding{
			RuleID: "TLS-PIN-FAILED", Severity: finding.SeverityHigh, OWASP: "ASK-02",
			Explanation: "could not obtain a TLS certificate pin: " + err.Error(),
		})
		//nolint:nilerr // pin failure is surfaced as a warning finding, not a hard error
		return ports.Resolution{PinnedRef: src.Ref, Warnings: warnings}, nil
	}
	return ports.Resolution{PinnedRef: src.Ref, CertSPKI: pin, Warnings: warnings}, nil
}

// TLSCertFetcher dials the host over TLS and pins the leaf certificate's SPKI.
type TLSCertFetcher struct {
	// InsecureSkipVerify disables chain verification (used only in tests against
	// httptest servers). Production leaves this false.
	InsecureSkipVerify bool
	// DialContext, when set, opens the raw TCP connection instead of a plain
	// net.Dialer. It runs after DNS resolution (the address is already
	// host:port), so a caller can enforce a destination policy — refusing
	// private, link-local, or metadata addresses — at the point the engine
	// itself would otherwise connect. Nil keeps the previous tls.Dialer
	// behaviour.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// SPKIPin satisfies CertFetcher.
func (f TLSCertFetcher) SPKIPin(ctx context.Context, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := parsed.Host
	if host == "" {
		return "", fmt.Errorf("url has no host: %q", rawURL)
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	// tls.Dialer fills ServerName from the address on its own; tls.Client
	// does not, so the hooked path sets it here or every verified handshake
	// fails before it starts.
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		return "", fmt.Errorf("url host %q: %w", host, err)
	}
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: f.InsecureSkipVerify} //nolint:gosec // opt-in for tests only

	var tconn *tls.Conn
	if f.DialContext != nil {
		raw, err := f.DialContext(ctx, "tcp", host)
		if err != nil {
			return "", fmt.Errorf("dial %s: %w", host, err)
		}
		tconn = tls.Client(raw, cfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = tconn.Close()
			return "", fmt.Errorf("tls handshake with %s: %w", host, err)
		}
	} else {
		dialer := &tls.Dialer{Config: cfg}
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return "", err
		}
		var ok bool
		tconn, ok = conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			return "", fmt.Errorf("unexpected connection type %T", conn)
		}
	}
	defer func() { _ = tconn.Close() }()

	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no peer certificate from %s", host)
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
