// Package proxy implements Component 2's egress proxy: a local forward proxy
// the shim points wrapped MCP servers at via HTTP(S)_PROXY.
//
// It enforces the policy's per-server host rules (policy.DecideHost), redacts
// known credential shapes from plain-HTTP request bodies before forwarding,
// and audits every connection — host, method, bytes both ways, redactions,
// allowed or denied. HTTPS rides CONNECT tunnels, which the proxy cannot see
// inside (no TLS interception in this slice): there the protection is the
// host allowlist and byte accounting, not body redaction.
//
// Until the sandbox slice lands, routing through the proxy is cooperative —
// a hostile server can ignore the env vars. The audit trail still catches
// every well-behaved library, which is most exfiltration in practice.
package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/policy"
	"github.com/alexverify/eyebrow/internal/domain/secrets"
)

// Deps are the proxy's collaborators.
type Deps struct {
	Audit ports.AuditSink
	Clock ports.Clock
}

// Options bind the proxy to one wrapped server's session and rules.
type Options struct {
	Server  string
	Session string
	Policy  policy.Policy
}

// Proxy is one listening egress proxy instance.
type Proxy struct {
	deps Deps
	opts Options
	ln   net.Listener
	srv  *http.Server
}

// New constructs a Proxy (not yet listening).
func New(deps Deps, opts Options) *Proxy {
	return &Proxy{deps: deps, opts: opts}
}

// Start listens on a loopback port and serves until Close. It returns the
// address (host:port) to put in HTTP(S)_PROXY.
func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.ln = ln
	p.srv = &http.Server{Handler: p}
	go p.srv.Serve(ln)
	return ln.Addr().String(), nil
}

// Close stops the listener.
func (p *Proxy) Close() error {
	if p.srv != nil {
		return p.srv.Close()
	}
	return nil
}

// ServeHTTP dispatches tunnels and plain HTTP.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveTunnel(w, r)
		return
	}
	p.servePlain(w, r)
}

// event returns a pre-filled egress event.
func (p *Proxy) event(host, method string) audit.Event {
	return audit.Event{
		At: p.deps.Clock.Now(), Session: p.opts.Session, Server: p.opts.Server,
		Kind: audit.KindEgress, Host: host, Method: method,
	}
}

func (p *Proxy) emit(e audit.Event) { _ = p.deps.Audit.Emit(context.Background(), e) }

// deny answers a blocked connection and audits the attempt — the attempt is
// the signal, so it is always logged.
func (p *Proxy) deny(w http.ResponseWriter, e audit.Event, reason string) {
	e.Status = audit.StatusDenied
	e.Detail = reason
	p.emit(e)
	http.Error(w, "eyebrow egress policy: "+reason, http.StatusForbidden)
}

// servePlain forwards an absolute-URI HTTP request with its body redacted.
func (p *Proxy) servePlain(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	e := p.event(host, r.Method)
	if d := p.opts.Policy.DecideHost(p.opts.Server, host); !d.Allowed {
		p.deny(w, e, d.Reason)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	redacted, matches := secrets.Redact(body)
	e.Redactions = len(matches)
	e.Detail = redactionKinds(matches)
	e.BytesUp = int64(len(redacted))

	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), strings.NewReader(string(redacted)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)
	out.ContentLength = int64(len(redacted))

	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		e.Status = audit.StatusError
		e.Detail = err.Error()
		p.emit(e)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	e.BytesDown = n
	e.Status = audit.StatusOK
	p.emit(e)
}

// serveTunnel relays a CONNECT tunnel, counting bytes in both directions.
func (p *Proxy) serveTunnel(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	e := p.event(host, http.MethodConnect)
	if d := p.opts.Policy.DecideHost(p.opts.Server, host); !d.Allowed {
		p.deny(w, e, d.Reason)
		return
	}

	upstream, err := net.Dial("tcp", hostPort)
	if err != nil {
		e.Status = audit.StatusError
		e.Detail = err.Error()
		p.emit(e)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var up, down atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, client)
		up.Store(n)
		upstream.Close()
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		down.Store(n)
		client.Close()
		done <- struct{}{}
	}()
	go func() {
		<-done
		<-done
		e.BytesUp = up.Load()
		e.BytesDown = down.Load()
		e.Status = audit.StatusOK
		p.emit(e)
	}()
}

func redactionKinds(ms []secrets.Match) string {
	if len(ms) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var kinds []string
	for _, m := range ms {
		if !seen[m.Kind] {
			seen[m.Kind] = true
			kinds = append(kinds, m.Kind)
		}
	}
	return "redacted: " + strings.Join(kinds, ", ")
}

// stripHopByHop removes headers that must not be forwarded by a proxy.
func stripHopByHop(h http.Header) {
	for _, k := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
