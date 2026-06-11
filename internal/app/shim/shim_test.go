package shim_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/app/apptest"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/app/shim"
	"github.com/alexverify/agentguard/internal/domain/audit"
)

// runRelay drives one relay session: clientLines go in as the agent's stdin,
// server is a scripted responder keyed by exact request line. It returns what
// the fake server received and what the agent got back.
func runRelay(t *testing.T, clientLines []string, responses map[string][]string, sink ports.AuditSink) (serverGot, clientGot string) {
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
	err := svc.Run(context.Background(), shim.Options{Server: "github", Session: "s1"},
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
