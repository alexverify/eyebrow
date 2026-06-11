// Package audit models the events the MCP shim records: one line per tool
// call, plus session lifecycle markers. Pure domain — the JSONL writer lives
// in internal/adapters/auditlog.
//
// Events never carry raw tool-call arguments: arguments routinely contain
// secrets, so only their content digest is recorded. The digest still lets an
// investigator prove what was passed when they hold a candidate value.
package audit

import "time"

// Kind is the event type.
type Kind string

const (
	// KindSessionStart marks a shim attaching to a server.
	KindSessionStart Kind = "session_start"
	// KindToolCall records one completed (or unanswered) tools/call.
	KindToolCall Kind = "tool_call"
	// KindServerExit marks the wrapped server terminating.
	KindServerExit Kind = "server_exit"
)

// Statuses for KindToolCall events.
const (
	StatusOK         = "ok"
	StatusError      = "error"
	StatusUnanswered = "unanswered" // server died before responding
)

// Event is one audit line.
type Event struct {
	At         time.Time `json:"ts"`
	Session    string    `json:"session"` // random id tying one shim run together
	Server     string    `json:"server"`  // the wrapped MCP server's name
	Kind       Kind      `json:"kind"`
	Tool       string    `json:"tool,omitempty"`
	ArgsDigest string    `json:"argsDigest,omitempty"` // sha256 of the raw arguments JSON
	DurationMs int64     `json:"durationMs,omitempty"`
	Status     string    `json:"status,omitempty"`
	ErrCode    int       `json:"errCode,omitempty"`
	Detail     string    `json:"detail,omitempty"` // e.g. exit status for server_exit
}
