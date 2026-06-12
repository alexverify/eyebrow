package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/agentguard/internal/cli"
	"github.com/alexverify/agentguard/internal/domain/audit"
)

// fakeMCPServer writes a script that answers the first request line with a
// canned JSON-RPC response and exits.
func fakeMCPServer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.sh")
	script := `#!/bin/sh
read line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMcpShimRelaysAndAudits(t *testing.T) {
	server := fakeMCPServer(t)
	auditDir := t.TempDir()

	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{}}}` + "\n")

	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", auditDir, "--", "/bin/sh", server,
	})
	if code != 0 {
		t.Fatalf("mcp-shim exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"result":{"ok":true}`) {
		t.Fatalf("server response not relayed to stdout: %q", out.String())
	}

	events := readAuditEvents(t, auditDir)
	kinds := map[audit.Kind]audit.Event{}
	for _, e := range events {
		kinds[e.Kind] = e
	}
	for _, want := range []audit.Kind{audit.KindSessionStart, audit.KindToolCall, audit.KindServerExit} {
		if _, ok := kinds[want]; !ok {
			t.Errorf("missing %s event in %+v", want, events)
		}
	}
	if call := kinds[audit.KindToolCall]; call.Tool != "ping" || call.Status != audit.StatusOK || call.Server != "demo" {
		t.Errorf("tool_call = %+v", call)
	}
	if events[0].Session == "" {
		t.Error("events must carry a session id")
	}
}

// TestMcpShimEnforcesPolicy proves the full enforcement path: a denied call
// is answered by the shim, never reaches the server, and is audited.
func TestMcpShimEnforcesPolicy(t *testing.T) {
	dir := t.TempDir()
	received := filepath.Join(dir, "received.log")
	server := filepath.Join(dir, "server.sh")
	// The server records every line it receives; answers nothing.
	script := "#!/bin/sh\ncat > " + received + "\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "agentguard.policy.json")
	pol := `{"mcp": {"servers": {"demo": {"denyTools": ["delete_*"]}}}}`
	if err := os.WriteFile(policyPath, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(dir, "audit")

	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delete_repo","arguments":{"repo":"prod"}}}` + "\n")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", auditDir, "--policy", policyPath,
		"--", "/bin/sh", server,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errBuf.String())
	}

	if !strings.Contains(out.String(), `"id":42`) || !strings.Contains(out.String(), "agentguard policy") {
		t.Errorf("client must receive the denial for its id: %q", out.String())
	}
	if b, _ := os.ReadFile(received); strings.Contains(string(b), "delete_repo") {
		t.Errorf("denied call leaked to the server: %q", b)
	}
	for _, e := range readAuditEvents(t, auditDir) {
		if e.Kind == audit.KindToolCall {
			if e.Status != audit.StatusDenied || e.Tool != "delete_repo" {
				t.Errorf("tool_call event = %+v", e)
			}
			return
		}
	}
	t.Fatal("denial not audited")
}

func TestMcpShimRejectsBrokenPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "agentguard.policy.json")
	if err := os.WriteFile(policyPath, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	app.Stdin = strings.NewReader("")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--policy", policyPath,
		"--", "/bin/true",
	})
	if code != cli.ExitError {
		t.Fatalf("a malformed policy must fail loudly, got exit %d", code)
	}
}

// TestMcpShimInjectsEgressProxy: the wrapped server must see HTTP(S)_PROXY
// pointing at a live agentguard proxy.
func TestMcpShimInjectsEgressProxy(t *testing.T) {
	dir := t.TempDir()
	server := filepath.Join(dir, "server.sh")
	script := `#!/bin/sh
read line
printf '{"jsonrpc":"2.0","id":1,"result":{"proxy":"%s %s"}}\n' "$HTTP_PROXY" "$HTTPS_PROXY"
`
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--", "/bin/sh", server,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Fatalf("child must see HTTP(S)_PROXY set: %q", out.String())
	}

	// And --no-egress-proxy must leave the environment alone.
	app, out, _ = newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--no-egress-proxy",
		"--", "/bin/sh", server,
	})
	if strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Fatalf("--no-egress-proxy must not inject proxy env: %q", out.String())
	}
}

func TestMcpShimPropagatesExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failing.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	app.Stdin = strings.NewReader("")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--", "/bin/sh", path,
	})
	if code != 7 {
		t.Fatalf("exit = %d, want the child's 7", code)
	}
}

func TestMcpShimRequiresServerAndCommand(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"mcp-shim", "--server", "x"}); code != cli.ExitUsage {
		t.Fatalf("missing command must be a usage error, got %d", code)
	}
	app, _, _ = newApp()
	if code := app.Execute(context.Background(), []string{"mcp-shim", "--", "/bin/true"}); code != cli.ExitUsage {
		t.Fatalf("missing --server must be a usage error, got %d", code)
	}
}

func readAuditEvents(t *testing.T, dir string) []audit.Event {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no audit files written: %v", err)
	}
	var events []audit.Event
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var ev audit.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				t.Fatalf("bad audit line %q: %v", line, err)
			}
			events = append(events, ev)
		}
	}
	return events
}
