// Package jsonrpc models the slice of JSON-RPC 2.0 the MCP shim inspects.
//
// It is pure domain logic: Parse classifies one wire line (MCP stdio framing
// is newline-delimited JSON) and Tracker correlates tools/call requests with
// their responses. The relay always forwards the original bytes verbatim —
// these types exist for inspection and audit, never for re-serialization.
package jsonrpc

import (
	"encoding/json"
	"time"

	"github.com/alexverify/assay/internal/domain/digest"
)

// Kind classifies a wire line.
type Kind string

const (
	KindRequest      Kind = "request"
	KindResponse     Kind = "response"
	KindNotification Kind = "notification"
	// KindUnknown covers everything the shim forwards but does not understand:
	// non-JSON banner lines, batches, malformed frames. Never an error — an
	// observe-only relay must tolerate anything.
	KindUnknown Kind = "unknown"
)

// MethodToolCall is the MCP method the shim audits.
const MethodToolCall = "tools/call"

// Message is the inspected view of one line.
type Message struct {
	Kind     Kind
	ID       string // raw JSON token of the id ("1" vs "\"1\"" stay distinct)
	Method   string // requests and notifications
	ToolName string // params.name for tools/call requests
	ArgsJSON []byte // raw params.arguments for tools/call requests
	IsError  bool   // responses: error member present
	ErrCode  int    // responses: error.code
}

// wire is the superset of fields Parse looks at.
type wire struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

// Parse classifies a single line. It never fails: anything that is not a
// well-formed single JSON-RPC object comes back as KindUnknown.
func Parse(line []byte) Message {
	var w wire
	if err := json.Unmarshal(line, &w); err != nil {
		return Message{Kind: KindUnknown}
	}
	id := string(w.ID)
	if id == "null" {
		id = ""
	}
	switch {
	case w.Method != "" && id != "":
		m := Message{Kind: KindRequest, ID: id, Method: w.Method}
		if w.Method == MethodToolCall {
			m.ToolName = w.Params.Name
			m.ArgsJSON = w.Params.Arguments
		}
		return m
	case w.Method != "":
		return Message{Kind: KindNotification, Method: w.Method}
	case id != "" && w.Error != nil:
		return Message{Kind: KindResponse, ID: id, IsError: true, ErrCode: w.Error.Code}
	case id != "" && w.Result != nil:
		return Message{Kind: KindResponse, ID: id}
	default:
		return Message{Kind: KindUnknown}
	}
}

// ArgsDigest returns the content digest of a tools/call's raw arguments —
// the only form in which arguments ever reach the audit trail.
func (m Message) ArgsDigest() string { return digest.Inline(m.ArgsJSON) }

// Pending is an in-flight tools/call. Arguments are kept only as a digest —
// the audit trail must never hold raw values (they routinely contain secrets).
type Pending struct {
	ID         string
	Tool       string
	ArgsDigest string
	At         time.Time
}

// Completed is a tools/call whose response arrived.
type Completed struct {
	Tool       string
	ArgsDigest string
	Duration   time.Duration
	OK         bool
	ErrCode    int
}

// Tracker correlates tools/call requests with their responses by id.
type Tracker struct {
	pending map[string]Pending
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{pending: make(map[string]Pending)}
}

// Observe feeds one parsed message through the tracker. A tools/call request
// becomes pending; a response matching a pending id completes it and is
// returned. Everything else returns nil.
func (t *Tracker) Observe(m Message, at time.Time) *Completed {
	switch m.Kind {
	case KindRequest:
		if m.Method == MethodToolCall {
			t.pending[m.ID] = Pending{
				ID: m.ID, Tool: m.ToolName, ArgsDigest: m.ArgsDigest(), At: at,
			}
		}
	case KindResponse:
		p, ok := t.pending[m.ID]
		if !ok {
			return nil
		}
		delete(t.pending, m.ID)
		return &Completed{
			Tool:       p.Tool,
			ArgsDigest: p.ArgsDigest,
			Duration:   at.Sub(p.At),
			OK:         !m.IsError,
			ErrCode:    m.ErrCode,
		}
	}
	return nil
}

// Len reports the number of in-flight calls.
func (t *Tracker) Len() int { return len(t.pending) }

// Drain removes and returns all in-flight calls — used when the server dies
// so unanswered calls can be audited as failed.
func (t *Tracker) Drain() []Pending {
	out := make([]Pending, 0, len(t.pending))
	for _, p := range t.pending {
		out = append(out, p)
	}
	t.pending = make(map[string]Pending)
	return out
}
