package jsonrpc

import (
	"testing"
	"time"
)

func TestParseClassifiesRequest(t *testing.T) {
	m := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if m.Kind != KindRequest {
		t.Fatalf("Kind = %q, want request", m.Kind)
	}
	if m.Method != "tools/list" {
		t.Errorf("Method = %q", m.Method)
	}
	if m.ID != "1" {
		t.Errorf("ID = %q", m.ID)
	}
}

func TestParseExtractsToolCallName(t *testing.T) {
	m := Parse([]byte(`{"jsonrpc":"2.0","id":"a1","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`))
	if m.Kind != KindRequest || m.Method != "tools/call" {
		t.Fatalf("misclassified: %+v", m)
	}
	if m.ToolName != "read_file" {
		t.Errorf("ToolName = %q", m.ToolName)
	}
}

func TestParseClassifiesNotification(t *testing.T) {
	m := Parse([]byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`))
	if m.Kind != KindNotification {
		t.Fatalf("Kind = %q, want notification", m.Kind)
	}
	if m.ID != "" {
		t.Errorf("notification must have empty ID, got %q", m.ID)
	}
}

func TestParseClassifiesResponses(t *testing.T) {
	ok := Parse([]byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[]}}`))
	if ok.Kind != KindResponse || ok.IsError {
		t.Fatalf("result response misclassified: %+v", ok)
	}
	fail := Parse([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"no such method"}}`))
	if fail.Kind != KindResponse || !fail.IsError {
		t.Fatalf("error response misclassified: %+v", fail)
	}
	if fail.ErrCode != -32601 {
		t.Errorf("ErrCode = %d", fail.ErrCode)
	}
}

func TestParseDistinguishesStringAndNumberIDs(t *testing.T) {
	num := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"x"}`))
	str := Parse([]byte(`{"jsonrpc":"2.0","id":"1","method":"x"}`))
	if num.ID == str.ID {
		t.Fatalf("id 1 and id \"1\" must not collide, both = %q", num.ID)
	}
}

func TestParseToleratesGarbage(t *testing.T) {
	for _, line := range []string{
		"server v1.2.3 starting up...", // stdout banner
		"",
		"{not json",
		`[{"jsonrpc":"2.0","id":1,"method":"x"}]`, // batch: MCP doesn't use them
		`{"jsonrpc":"2.0"}`,                       // no method, no result/error
	} {
		m := Parse([]byte(line))
		if m.Kind != KindUnknown {
			t.Errorf("Parse(%q).Kind = %q, want unknown", line, m.Kind)
		}
	}
}

func TestTrackerCorrelatesCallAndResponse(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(100, 0)

	if done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run"}}`)), t0); done != nil {
		t.Fatal("a request must not complete anything")
	}
	done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":5,"result":{}}`)), t0.Add(250*time.Millisecond))
	if done == nil {
		t.Fatal("response must complete the pending call")
	}
	if done.Tool != "run" || !done.OK || done.Duration != 250*time.Millisecond {
		t.Errorf("completed = %+v", done)
	}
	// Same id again: nothing pending anymore.
	if again := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":5,"result":{}}`)), t0); again != nil {
		t.Error("a completed id must not complete twice")
	}
}

func TestTrackerCarriesArgsDigest(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(0, 0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"cmd":"ls"}}}`)), t0)
	done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)), t0)
	if done == nil || done.ArgsDigest == "" {
		t.Fatalf("completed call must carry an args digest, got %+v", done)
	}
	// Same args → same digest; different args → different digest.
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"cmd":"ls"}}}`)), t0)
	same := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`)), t0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"cmd":"rm"}}}`)), t0)
	diff := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":3,"result":{}}`)), t0)
	if same.ArgsDigest != done.ArgsDigest || diff.ArgsDigest == done.ArgsDigest {
		t.Errorf("digest stability broken: %q %q %q", done.ArgsDigest, same.ArgsDigest, diff.ArgsDigest)
	}
}

func TestTrackerErrorResponse(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(0, 0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"run"}}`)), t0)
	done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":"x","error":{"code":-32000,"message":"boom"}}`)), t0)
	if done == nil || done.OK || done.ErrCode != -32000 {
		t.Fatalf("completed = %+v", done)
	}
}

func TestTrackerIgnoresNonToolTraffic(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(0, 0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)), t0)
	if done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)), t0); done != nil {
		t.Fatal("non-tools/call requests must not be tracked")
	}
	if done := tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":99,"result":{}}`)), t0); done != nil {
		t.Fatal("a response with no pending request must be ignored")
	}
}

func TestTrackerDrain(t *testing.T) {
	tr := NewTracker()
	t0 := time.Unix(0, 0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}}`)), t0)
	tr.Observe(Parse([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}`)), t0)

	pending := tr.Drain()
	if len(pending) != 2 {
		t.Fatalf("Drain returned %d pending, want 2", len(pending))
	}
	if tr.Len() != 0 {
		t.Error("Drain must empty the tracker")
	}
}
