package resolve

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/assay/internal/domain/artifact"
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
