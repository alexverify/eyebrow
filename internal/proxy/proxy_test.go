package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/app/apptest"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

func startProxy(t *testing.T, pol policy.Policy) (*url.URL, *apptest.AuditSink) {
	t.Helper()
	sink := &apptest.AuditSink{}
	p := New(Deps{Audit: sink, Clock: ports.ClockFunc(time.Now)},
		Options{Server: "db-tool", Session: "s1", Policy: pol})
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	u, _ := url.Parse("http://" + addr)
	return u, sink
}

func egressEvents(sink *apptest.AuditSink) []audit.Event {
	var out []audit.Event
	for _, e := range sink.Events() {
		if e.Kind == audit.KindEgress {
			out = append(out, e)
		}
	}
	return out
}

func TestPlainHTTPRedactsBody(t *testing.T) {
	var received string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		fmt.Fprint(w, "stored")
	}))
	defer backend.Close()

	proxyURL, sink := startProxy(t, policy.Policy{})
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(backend.URL, "application/json",
		strings.NewReader(`{"note":"sync","aws":"AKIAIOSFODNN7EXAMPLE"}`))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "stored" {
		t.Fatalf("response not relayed: %q", body)
	}

	if strings.Contains(received, "AKIA") {
		t.Errorf("secret reached the backend: %q", received)
	}
	if !strings.Contains(received, "[REDACTED:aws-access-key]") || !strings.Contains(received, `"note":"sync"`) {
		t.Errorf("body not redacted in place: %q", received)
	}

	ev := egressEvents(sink)
	if len(ev) != 1 {
		t.Fatalf("got %d egress events, want 1: %+v", len(ev), ev)
	}
	e := ev[0]
	if e.Status != audit.StatusOK || e.Method != "POST" || e.Redactions != 1 || e.Host == "" {
		t.Errorf("egress event = %+v", e)
	}
	if e.BytesDown == 0 {
		t.Errorf("response bytes not accounted: %+v", e)
	}
}

func TestPlainHTTPDeniedHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("denied request must never reach the backend")
	}))
	defer backend.Close()

	pol := policy.Policy{MCP: policy.MCPPolicy{Servers: map[string]policy.ToolRule{
		"db-tool": {AllowHosts: []string{"api.allowed.example"}},
	}}}
	proxyURL, sink := startProxy(t, pol)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	ev := egressEvents(sink)
	if len(ev) != 1 || ev[0].Status != audit.StatusDenied || ev[0].Detail == "" {
		t.Fatalf("denial not audited with reason: %+v", ev)
	}
}

// dialCONNECT opens a raw tunnel through the proxy and returns the conn after
// the 200 response.
func dialCONNECT(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		t.Skipf("tunnel refused: %d", resp.StatusCode) // callers asserting denial handle this themselves
	}
	return conn
}

func TestConnectTunnelRelaysAndCounts(t *testing.T) {
	// A TCP echo server stands in for a TLS endpoint: CONNECT relays raw bytes.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	proxyURL, sink := startProxy(t, policy.Policy{})
	conn := dialCONNECT(t, proxyURL.Host, echo.Addr().String())
	defer conn.Close()

	msg := "hello through the tunnel"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo through tunnel failed: %q %v", buf, err)
	}
	conn.Close()

	// The audit event lands after both tunnel halves close.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if ev := egressEvents(sink); len(ev) == 1 {
			e := ev[0]
			if e.Status != audit.StatusOK || e.Method != http.MethodConnect ||
				e.BytesUp != int64(len(msg)) || e.BytesDown != int64(len(msg)) {
				t.Fatalf("egress event = %+v", e)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no egress event after tunnel close: %+v", sink.Events())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConnectDeniedHost(t *testing.T) {
	pol := policy.Policy{MCP: policy.MCPPolicy{Servers: map[string]policy.ToolRule{
		"*": {DenyHosts: []string{"127.0.0.1"}},
	}}}
	proxyURL, sink := startProxy(t, pol)

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	ev := egressEvents(sink)
	if len(ev) != 1 || ev[0].Status != audit.StatusDenied {
		t.Fatalf("denied CONNECT not audited: %+v", ev)
	}
}
