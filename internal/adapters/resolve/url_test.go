package resolve

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

type fakeCertFetcher struct {
	pin string
	err error
}

func (f fakeCertFetcher) SPKIPin(context.Context, string) (string, error) { return f.pin, f.err }

func TestURLResolvePinsSPKI(t *testing.T) {
	u := URL{Fetcher: fakeCertFetcher{pin: "sha256/AAAA"}}
	res, err := u.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceURL, Ref: "https://api.example.com/sse"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.CertSPKI != "sha256/AAAA" {
		t.Errorf("CertSPKI = %q", res.CertSPKI)
	}
	if res.PinnedRef != "https://api.example.com/sse" {
		t.Errorf("PinnedRef = %q", res.PinnedRef)
	}
	if !hasRule(res.Warnings, "REMOTE-UNHASHABLE") {
		t.Error("remote sources must carry the REMOTE-UNHASHABLE note")
	}
}

func TestURLResolveDegradesOnFetchError(t *testing.T) {
	u := URL{Fetcher: fakeCertFetcher{err: errors.New("handshake failed")}}
	res, err := u.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceURL, Ref: "https://bad.example"})
	if err != nil {
		t.Fatalf("Resolve must not hard-fail: %v", err)
	}
	if res.CertSPKI != "" {
		t.Errorf("CertSPKI should be empty on error, got %q", res.CertSPKI)
	}
	if !hasRule(res.Warnings, "TLS-PIN-FAILED") {
		t.Error("expected TLS-PIN-FAILED warning")
	}
}

func TestTLSCertFetcherAgainstLocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	pin, err := (TLSCertFetcher{InsecureSkipVerify: true}).SPKIPin(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("SPKIPin: %v", err)
	}
	if len(pin) < len("sha256/") || pin[:len("sha256/")] != "sha256/" {
		t.Fatalf("pin = %q, want sha256/ prefix", pin)
	}
}

// TestTLSCertFetcherUsesDialContextHook proves the fetcher dials through a
// caller-supplied hook rather than a bare net.Dialer, and that the hook sees
// the resolved host:port (the point at which a destination policy can act,
// after DNS but before any bytes are exchanged).
func TestTLSCertFetcherUsesDialContextHook(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	var gotNetwork, gotAddress string
	hook := func(ctx context.Context, network, address string) (net.Conn, error) {
		gotNetwork, gotAddress = network, address
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}

	pin, err := (TLSCertFetcher{InsecureSkipVerify: true, DialContext: hook}).SPKIPin(context.Background(), "https://pinned.example.invalid")
	if err != nil {
		t.Fatalf("SPKIPin: %v", err)
	}
	if gotNetwork != "tcp" {
		t.Errorf("network = %q, want tcp", gotNetwork)
	}
	if gotAddress != "pinned.example.invalid:443" {
		t.Errorf("address = %q, want pinned.example.invalid:443", gotAddress)
	}
	if len(pin) < len("sha256/") || pin[:len("sha256/")] != "sha256/" {
		t.Fatalf("pin = %q, want sha256/ prefix", pin)
	}
}

// TestTLSCertFetcherWrapsDialContextError proves a hook's refusal (e.g. a
// destination policy denying a private address) surfaces with its message
// intact, rather than being swallowed or replaced.
func TestTLSCertFetcherWrapsDialContextError(t *testing.T) {
	wantErr := errors.New("destination refused: private address")
	hook := func(context.Context, string, string) (net.Conn, error) {
		return nil, wantErr
	}
	_, err := (TLSCertFetcher{DialContext: hook}).SPKIPin(context.Background(), "https://10.0.0.5")
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("SPKIPin error = %v, want to contain %q", err, wantErr.Error())
	}
}

// TestURLResolveUsesDialContextHook proves Resolve routes the TLS probe
// through the fetcher's DialContext hook and still produces a pin.
func TestURLResolveUsesDialContextHook(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	var gotAddress string
	hook := func(ctx context.Context, network, address string) (net.Conn, error) {
		gotAddress = address
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}

	u := URL{Fetcher: TLSCertFetcher{InsecureSkipVerify: true, DialContext: hook}}
	res, err := u.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceURL, Ref: "https://pinned.example.invalid/sse"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotAddress != "pinned.example.invalid:443" {
		t.Errorf("address = %q, want pinned.example.invalid:443", gotAddress)
	}
	if res.CertSPKI == "" {
		t.Error("expected a pin obtained through the hook")
	}
}

// TestURLResolveSurfacesDialContextError proves a hook's error message
// survives into the TLS-PIN-FAILED finding, so a hosted caller can see why a
// connection was refused.
func TestURLResolveSurfacesDialContextError(t *testing.T) {
	wantErr := errors.New("destination refused: private address")
	hook := func(context.Context, string, string) (net.Conn, error) {
		return nil, wantErr
	}
	u := URL{Fetcher: TLSCertFetcher{DialContext: hook}}
	res, err := u.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceURL, Ref: "https://10.0.0.5/sse"})
	if err != nil {
		t.Fatalf("Resolve must not hard-fail on a dial refusal: %v", err)
	}
	if !hasRule(res.Warnings, "TLS-PIN-FAILED") {
		t.Fatal("expected a TLS-PIN-FAILED warning")
	}
	var explanation string
	for _, w := range res.Warnings {
		if w.RuleID == "TLS-PIN-FAILED" {
			explanation = w.Explanation
		}
	}
	if !strings.Contains(explanation, wantErr.Error()) {
		t.Fatalf("explanation %q does not contain the hook's error", explanation)
	}
}
