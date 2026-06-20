// Package shim implements the MCP interposition relay — the heart of
// `eyebrow wrap` (Component 2).
//
// The relay sits between an AI tool (the client) and a real MCP server,
// pumping newline-delimited JSON-RPC in both directions. Allowed traffic is
// forwarded byte-for-byte — inspection happens on a parsed copy, the wire is
// never re-serialized — and every tools/call is audited, correlating each
// request with its response. Calls the policy denies never reach the server:
// the shim answers the client itself with a JSON-RPC error and audits the
// denial.
package shim

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/jsonrpc"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// Deps are the relay's collaborators.
type Deps struct {
	Audit ports.AuditSink
	Clock ports.Clock
}

// Service relays one client↔server session.
type Service struct {
	deps Deps
}

// New constructs a relay Service.
func New(d Deps) *Service { return &Service{deps: d} }

// Options identify the session being relayed.
type Options struct {
	Server  string        // the wrapped MCP server's name (from the tool config)
	Session string        // caller-generated id tying this run's events together
	Policy  policy.Policy // runtime tool rules; zero value allows everything
	Sandbox string        // active sandbox backend name, recorded on session_start
}

// Run pumps clientIn→serverIn and serverOut→clientOut until the server side
// closes, auditing tool calls along the way. It returns when the server's
// output ends (normal shutdown or crash); unanswered calls are audited as
// such. Audit failures are deliberately swallowed — an observe-only relay
// must never break the session it watches.
func (s *Service) Run(ctx context.Context, opts Options, clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	var (
		mu      sync.Mutex
		tracker = jsonrpc.NewTracker()
	)
	s.emit(ctx, audit.Event{
		At: s.deps.Clock.Now(), Session: opts.Session, Server: opts.Server,
		Kind: audit.KindSessionStart, Detail: sandboxDetail(opts.Sandbox),
	})

	// Both pumps write to the client (the up pump relays, the down pump
	// answers denials), so client writes must be line-atomic.
	toClient := &lockedWriter{w: clientOut}

	observe := func(m jsonrpc.Message) *jsonrpc.Completed {
		mu.Lock()
		defer mu.Unlock()
		return tracker.Observe(m, s.deps.Clock.Now())
	}

	// Client → server: enforce policy on tools/call, track what's forwarded.
	// When the client hangs up, propagate EOF so the server can shut down.
	go func() {
		pump(clientIn, serverIn, func(line []byte) bool {
			m := jsonrpc.Parse(line)
			if m.Kind == jsonrpc.KindRequest && m.Method == jsonrpc.MethodToolCall {
				if d := opts.Policy.DecideTool(opts.Server, m.ToolName); !d.Allowed {
					s.deny(ctx, opts, m, d, toClient)
					return false // never reaches the server
				}
			}
			observe(m)
			return true
		})
		if c, ok := serverIn.(io.Closer); ok {
			c.Close()
		}
	}()

	// Server → client: complete pending calls, forward verbatim. This side
	// ending means the session is over.
	err := pump(serverOut, toClient, func(line []byte) bool {
		if done := observe(jsonrpc.Parse(line)); done != nil {
			s.emit(ctx, audit.Event{
				At: s.deps.Clock.Now(), Session: opts.Session, Server: opts.Server,
				Kind: audit.KindToolCall, Tool: done.Tool, ArgsDigest: done.ArgsDigest,
				DurationMs: done.Duration.Milliseconds(),
				Status:     status(done), ErrCode: done.ErrCode,
			})
		}
		return true
	})

	mu.Lock()
	pending := tracker.Drain()
	mu.Unlock()
	for _, p := range pending {
		s.emit(ctx, audit.Event{
			At: s.deps.Clock.Now(), Session: opts.Session, Server: opts.Server,
			Kind: audit.KindToolCall, Tool: p.Tool, ArgsDigest: p.ArgsDigest,
			Status: audit.StatusUnanswered,
		})
	}
	return err
}

// pump copies src to dst line by line. inspect sees every line and decides
// whether it is forwarded (untouched) or swallowed. The final unterminated
// line (if any) is handled too. Returns nil on EOF; only a write failure is
// an error.
func pump(src io.Reader, dst io.Writer, inspect func(line []byte) bool) error {
	r := bufio.NewReaderSize(src, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && inspect(line) {
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}
		}
		if err != nil {
			return nil // EOF or closed pipe: the session is simply over
		}
	}
}

// deny answers a blocked tools/call with a JSON-RPC error and audits it. The
// id is echoed back as the raw token from the request, so the client matches
// the response no matter what id type it used.
func (s *Service) deny(ctx context.Context, opts Options, m jsonrpc.Message, d policy.Decision, toClient io.Writer) {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: json.RawMessage(m.ID)}
	resp.Error.Code = DeniedErrorCode
	resp.Error.Message = fmt.Sprintf("eyebrow policy: tool %q denied for server %q (%s)", m.ToolName, opts.Server, d.Reason)

	if line, err := json.Marshal(resp); err == nil {
		_, _ = toClient.Write(append(line, '\n'))
	}
	s.emit(ctx, audit.Event{
		At: s.deps.Clock.Now(), Session: opts.Session, Server: opts.Server,
		Kind: audit.KindToolCall, Tool: m.ToolName, ArgsDigest: m.ArgsDigest(),
		Status: audit.StatusDenied, ErrCode: DeniedErrorCode, Detail: d.Reason,
	})
}

// DeniedErrorCode is the JSON-RPC error code the shim uses for policy
// denials, in the implementation-defined server-error range.
const DeniedErrorCode = -32001

// lockedWriter serializes writes from both pumps onto one stream.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

func (s *Service) emit(ctx context.Context, e audit.Event) {
	_ = s.deps.Audit.Emit(ctx, e) // best-effort by design
}

func status(c *jsonrpc.Completed) string {
	if c.OK {
		return audit.StatusOK
	}
	return audit.StatusError
}

// sandboxDetail renders the session_start detail describing confinement.
func sandboxDetail(backend string) string {
	if backend == "" {
		backend = "none"
	}
	return "sandbox=" + backend
}
