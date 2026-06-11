// Package shim implements the MCP interposition relay — the heart of
// `agentguard wrap` (Component 2, observe-only slice).
//
// The relay sits between an AI tool (the client) and a real MCP server,
// pumping newline-delimited JSON-RPC in both directions. It forwards every
// byte verbatim — inspection happens on a parsed copy, the wire is never
// re-serialized — and emits one audit event per tools/call, correlating each
// request with its response. It blocks nothing and modifies nothing; policy
// enforcement is the next slice.
package shim

import (
	"bufio"
	"context"
	"io"
	"sync"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/domain/jsonrpc"
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
	Server  string // the wrapped MCP server's name (from the tool config)
	Session string // caller-generated id tying this run's events together
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
		Kind: audit.KindSessionStart,
	})

	observe := func(line []byte) *jsonrpc.Completed {
		mu.Lock()
		defer mu.Unlock()
		return tracker.Observe(jsonrpc.Parse(line), s.deps.Clock.Now())
	}

	// Client → server: track outgoing requests, forward verbatim. When the
	// client hangs up, propagate EOF so the server can shut down.
	go func() {
		pump(clientIn, serverIn, func(line []byte) { observe(line) })
		if c, ok := serverIn.(io.Closer); ok {
			c.Close()
		}
	}()

	// Server → client: complete pending calls, forward verbatim. This side
	// ending means the session is over.
	err := pump(serverOut, clientOut, func(line []byte) {
		if done := observe(line); done != nil {
			s.emit(ctx, audit.Event{
				At: s.deps.Clock.Now(), Session: opts.Session, Server: opts.Server,
				Kind: audit.KindToolCall, Tool: done.Tool, ArgsDigest: done.ArgsDigest,
				DurationMs: done.Duration.Milliseconds(),
				Status:     status(done), ErrCode: done.ErrCode,
			})
		}
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

// pump copies src to dst line by line, handing each line to inspect before
// forwarding it untouched. The final unterminated line (if any) is forwarded
// too. Returns nil on EOF; only a write failure is an error.
func pump(src io.Reader, dst io.Writer, inspect func(line []byte)) error {
	r := bufio.NewReaderSize(src, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			inspect(line)
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}
		}
		if err != nil {
			return nil // EOF or closed pipe: the session is simply over
		}
	}
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
