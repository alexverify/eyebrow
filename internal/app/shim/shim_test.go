package shim_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/assay/internal/app/apptest"
	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/app/shim"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/policy"
)

// runRelay drives one relay session: clientLines go in as the agent's stdin,
// server is a scripted responder keyed by exact request line. It returns what
// the fake server received and what the agent got back.
func runRelay(t *testing.T, clientLines []string, responses map[string][]string, sink ports.AuditSink) (serverGot, clientGot string) {
	t.Helper()
	return runRelayPolicy(t, clientLines, responses, sink, policy.Policy{})
}

func runRelayPolicy(t *testing.T, clientLines []string, responses map[string][]string, sink ports.AuditSink, pol policy.Policy) (serverGot, clientGot string) {
	t.Helper()

	clientIn := strings.NewReader(strings.Join(clientLines, ""))
	var clientOut bytes.Buffer

	serverInR, serverInW := io.Pipe()   // relay writes → server reads
	serverOutR, serverOutW := io.Pipe() // server writes → relay reads

	var received bytes.Buffer
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer serverOutW.Close()
		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 4096)
		for {
			n, err := serverInR.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				received.Write(tmp[:n])
				for {
					nl := bytes.IndexByte(buf, '\n')
					if nl < 0 {
						break
					}
					line := string(buf[:nl+1])
					buf = buf[nl+1:]
					for _, resp := range responses[line] {
						if _, err := serverOutW.Write([]byte(resp)); err != nil {
							return
						}
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	svc := shim.New(shim.Deps{Audit: sink, Clock: ports.ClockFunc(time.Now)})
	err := svc.Run(context.Background(), shim.Options{Server: "github", Session: "s1", Policy: pol},
		clientIn, &clientOut, serverInW, serverOutR)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-serverDone
	return received.String(), clientOut.String()
}

const (
	callLine = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"x"}}}` + "\n"
	respLine = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}` + "\n"
)

func TestRelayIsByteTransparent(t *testing.T) {
	banner := "github-mcp v2 ready\n" // non-JSON noise some servers print
	listLine := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	listResp := `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}` + "\n"

	sink := &apptest.AuditSink{}
	serverGot, clientGot := runRelay(t,
		[]string{callLine, listLine},
		map[string][]string{
			callLine: {banner, respLine},
			listLine: {listResp},
		}, sink)

	if serverGot != callLine+listLine {
		t.Errorf("server received altered bytes:\n%q", serverGot)
	}
	if clientGot != banner+respLine+listResp {
		t.Errorf("client received altered bytes:\n%q", clientGot)
	}
}

func TestRelayAuditsToolCalls(t *testing.T) {
	sink := &apptest.AuditSink{}
	runRelay(t, []string{callLine}, map[string][]string{callLine: {respLine}}, sink)

	events := sink.Events()
	var calls []audit.Event
	for _, e := range events {
		if e.Kind == audit.KindToolCall {
			calls = append(calls, e)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("got %d tool_call events, want 1: %+v", len(calls), events)
	}
	c := calls[0]
	if c.Tool != "create_issue" || c.Status != audit.StatusOK || c.Server != "github" || c.Session != "s1" {
		t.Errorf("event = %+v", c)
	}
	if c.ArgsDigest == "" {
		t.Error("tool_call event must carry the args digest")
	}
	if events[0].Kind != audit.KindSessionStart {
		t.Errorf("first event must be session_start, got %+v", events[0])
	}
}

func TestRelayAuditsErrorResponses(t *testing.T) {
	errResp := `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}` + "\n"
	sink := &apptest.AuditSink{}
	runRelay(t, []string{callLine}, map[string][]string{callLine: {errResp}}, sink)

	for _, e := range sink.Events() {
		if e.Kind == audit.KindToolCall {
			if e.Status != audit.StatusError || e.ErrCode != -32000 {
				t.Errorf("event = %+v", e)
			}
			return
		}
	}
	t.Fatal("no tool_call event emitted")
}

func TestRelayAuditsUnansweredCallsWhenServerDies(t *testing.T) {
	// Server responds to nothing: its output closes as soon as input ends.
	sink := &apptest.AuditSink{}
	runRelay(t, []string{callLine}, map[string][]string{}, sink)

	for _, e := range sink.Events() {
		if e.Kind == audit.KindToolCall && e.Status == audit.StatusUnanswered && e.Tool == "create_issue" {
			return
		}
	}
	t.Fatalf("expected an unanswered tool_call event, got %+v", sink.Events())
}

func TestRelayDeniesByPolicy(t *testing.T) {
	pol := policy.Policy{MCP: policy.MCPPolicy{Servers: map[string]policy.ToolRule{
		"github": {DenyTools: []string{"create_*"}},
	}}}
	sink := &apptest.AuditSink{}
	serverGot, clientGot := runRelayPolicy(t, []string{callLine}, map[string][]string{}, sink, pol)

	if serverGot != "" {
		t.Errorf("a denied call must never reach the server, got %q", serverGot)
	}
	if !strings.Contains(clientGot, `"id":1`) || !strings.Contains(clientGot, `"error"`) ||
		!strings.Contains(clientGot, "assay policy") {
		t.Errorf("client must get a JSON-RPC error for its id: %q", clientGot)
	}

	var denied *audit.Event
	for _, e := range sink.Events() {
		if e.Kind == audit.KindToolCall {
			e := e
			denied = &e
		}
	}
	if denied == nil || denied.Status != audit.StatusDenied {
		t.Fatalf("denial must be audited, got %+v", sink.Events())
	}
	if denied.Tool != "create_issue" || denied.ArgsDigest == "" || !strings.Contains(denied.Detail, "create_*") {
		t.Errorf("denied event = %+v", denied)
	}
}

func TestRelayAllowsAndDeniesSideBySide(t *testing.T) {
	pol := policy.Policy{MCP: policy.MCPPolicy{Servers: map[string]policy.ToolRule{
		"*": {DenyTools: []string{"delete_*"}},
	}}}
	deniedLine := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}` + "\n"

	sink := &apptest.AuditSink{}
	serverGot, clientGot := runRelayPolicy(t,
		[]string{callLine, deniedLine},
		map[string][]string{callLine: {respLine}}, sink, pol)

	if serverGot != callLine {
		t.Errorf("only the allowed call may reach the server, got %q", serverGot)
	}
	if !strings.Contains(clientGot, `"result"`) || !strings.Contains(clientGot, `"error"`) {
		t.Errorf("client must see the real response AND the denial: %q", clientGot)
	}

	statuses := map[string]string{}
	for _, e := range sink.Events() {
		if e.Kind == audit.KindToolCall {
			statuses[e.Tool] = e.Status
		}
	}
	if statuses["create_issue"] != audit.StatusOK || statuses["delete_repo"] != audit.StatusDenied {
		t.Errorf("statuses = %v", statuses)
	}
}

func TestRelayHandlesOversizedLines(t *testing.T) {
	big := strings.Repeat("x", 2<<20) // 2 MiB payload
	bigCall := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"upload","arguments":{"data":"` + big + `"}}}` + "\n"
	bigResp := `{"jsonrpc":"2.0","id":9,"result":{"echo":"` + big + `"}}` + "\n"

	sink := &apptest.AuditSink{}
	serverGot, clientGot := runRelay(t, []string{bigCall}, map[string][]string{bigCall: {bigResp}}, sink)

	if serverGot != bigCall {
		t.Error("oversized request corrupted in transit")
	}
	if clientGot != bigResp {
		t.Error("oversized response corrupted in transit")
	}
	for _, e := range sink.Events() {
		if e.Kind == audit.KindToolCall && e.Status == audit.StatusOK {
			return
		}
	}
	t.Error("oversized call not audited")
}
