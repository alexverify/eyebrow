package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostSendsTextPayload(t *testing.T) {
	var got map[string]string
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := New().Post(context.Background(), srv.URL, "1 drifted, 0 new"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "1 drifted, 0 new" {
		t.Errorf("payload text = %q", got["text"])
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}

func TestPostErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := New().Post(context.Background(), srv.URL, "x"); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

// A zero-value Sender has a nil Client and must fall back to http.DefaultClient.
func TestPostZeroValueSenderUsesDefaultClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var s Sender // Client is nil
	if err := s.Post(context.Background(), srv.URL, "hi"); err != nil {
		t.Fatalf("zero-value Sender should post via the default client: %v", err)
	}
}

// A transport failure (here: a cancelled context) is returned, not swallowed.
func TestPostTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New().Post(ctx, srv.URL, "x"); err == nil {
		t.Error("expected a transport error from a cancelled context")
	}
}
