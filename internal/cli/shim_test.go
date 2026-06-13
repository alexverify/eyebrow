package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexverify/agentguard/internal/cli"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/sandbox"
)

// shell resolves a POSIX sh for the shim integration tests (which drive fake
// MCP servers written as shell scripts), skipping when none is present — e.g.
// a Windows host without Git Bash on PATH. The relay logic itself is OS-
// agnostic and covered by the in-memory tests in internal/app/shim.
func shell(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh on PATH; shim integration test needs a shell")
	}
	return p
}

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
		"mcp-shim", "--server", "demo", "--audit-dir", auditDir, "--", shell(t), server,
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
		"--", shell(t), server,
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
	// AGENTGUARD_CONTROL is injected below as a control: it proves the child
	// receives our custom environment at all, isolating proxy-var issues from
	// shell env-passthrough issues.
	script := `#!/bin/sh
read line
printf '{"jsonrpc":"2.0","id":1,"result":{"proxy":"%s","ctrl":"%s"}}\n' "$HTTP_PROXY" "$AGENTGUARD_CONTROL"
`
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTGUARD_CONTROL", "present")

	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--", shell(t), server,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errBuf.String())
	}
	// The control var proves our custom environment reaches the child — the
	// OS-agnostic part of proxy injection.
	if !strings.Contains(out.String(), `"ctrl":"present"`) {
		t.Fatalf("child did not receive the injected environment: %q", out.String())
	}
	// The HTTP_PROXY value check uses a bash fake server. On Windows, Git Bash's
	// MSYS layer mangles env-var values that look like paths ("http://…:port"),
	// so the script sees it empty even though child.Env carries it correctly —
	// real Windows MCP servers are native exes and read it intact. The Go-level
	// injection is identical across OSes, so asserting the value on Unix covers it.
	if runtime.GOOS != "windows" && !strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Fatalf("child must see HTTP_PROXY set: %q", out.String())
	}

	// And --no-egress-proxy must leave the environment alone.
	app, out, _ = newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--no-egress-proxy",
		"--", shell(t), server,
	})
	if strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Fatalf("--no-egress-proxy must not inject proxy env: %q", out.String())
	}
}

// TestMcpShimSandboxConfinesWrites runs only where a real sandbox backend is
// present. The model is permissive reads but locked-down writes, so the test
// proves the server can write inside its workspace but not outside it.
func TestMcpShimSandboxConfinesWrites(t *testing.T) {
	if sandbox.Select(sandbox.Profile{}).Name() == "none" {
		t.Skip("no sandbox backend on this host")
	}
	work := t.TempDir()
	// The outside target must be normally writable yet outside the workspace
	// and the scratch (temp) dirs the sandbox allows — a unique file under
	// $HOME fits. t.TempDir() would not: it lives under TMPDIR, which the
	// sandbox permits for scratch writes.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	outside := filepath.Join(home, fmt.Sprintf(".agentguard_escape_%d.txt", os.Getpid()))
	t.Cleanup(func() { os.Remove(outside) })
	server := filepath.Join(work, "server.sh")
	script := "#!/bin/sh\nread line\n" +
		"if echo x > " + filepath.Join(work, "inside.txt") + " 2>/dev/null; then i=ok; else i=denied; fi\n" +
		"if echo x > " + outside + " 2>/dev/null; then o=leaked; else o=denied; fi\n" +
		`printf '{"jsonrpc":"2.0","id":1,"result":{"in":"%s","out":"%s"}}\n' "$i" "$o"` + "\n"
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}` + "\n")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(),
		"--workspace", work, "--no-egress-proxy", "--", shell(t), server,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"in":"ok"`) {
		t.Errorf("workspace write was wrongly denied: %q", out.String())
	}
	if !strings.Contains(out.String(), `"out":"denied"`) {
		t.Errorf("sandbox failed to deny out-of-workspace write: %q", out.String())
	}
}

// TestMcpShimSandboxBlocksOffProxyEgress is the payoff of the slice: with the
// sandbox on, a server bypassing HTTP_PROXY to hit a host directly cannot
// connect (network is confined to the proxy port); with --no-sandbox it can.
func TestMcpShimSandboxBlocksOffProxyEgress(t *testing.T) {
	if sandbox.Select(sandbox.Profile{}).Name() == "none" {
		t.Skip("no sandbox backend on this host")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	// A listener the server will try to reach directly (bypassing the proxy).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nREACHED"))
			c.Close()
		}
	}()
	target := "http://" + ln.Addr().String() + "/"

	run := func(extra ...string) string {
		work := t.TempDir()
		server := filepath.Join(work, "server.sh")
		// --noproxy '*' forces a direct connection, ignoring HTTP(S)_PROXY.
		script := "#!/bin/sh\nread line\n" +
			"r=$(curl -s --noproxy '*' --max-time 3 " + target + " 2>/dev/null)\n" +
			`printf '{"jsonrpc":"2.0","id":1,"result":{"got":"%s"}}\n' "$r"` + "\n"
		if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		app, out, _ := newApp()
		app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}` + "\n")
		args := append([]string{"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--workspace", work}, extra...)
		args = append(args, "--", shell(t), server)
		app.Execute(context.Background(), args)
		return out.String()
	}

	if got := run("--no-sandbox"); !strings.Contains(got, "REACHED") {
		t.Fatalf("control: unsandboxed server should reach the listener, got %q", got)
	}
	if got := run(); strings.Contains(got, "REACHED") {
		t.Fatalf("sandbox failed to block a direct off-proxy connection: %q", got)
	}
}

func TestMcpShimNoSandboxFlag(t *testing.T) {
	// With --no-sandbox the server runs unconfined and can read anywhere.
	server := fakeMCPServer(t)
	app, out, errBuf := newApp()
	app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{}}}` + "\n")
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(),
		"--no-sandbox", "--no-egress-proxy", "--", shell(t), server,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"ok":true`) {
		t.Fatalf("server did not run: %q", out.String())
	}
}

func TestMcpShimPropagatesExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failing.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newApp()
	app.Stdin = strings.NewReader("")
	// --no-sandbox: this asserts exit-code propagation, not confinement. Under
	// a sandbox the script (in a temp dir outside the workspace) would be
	// unreadable and the wrapper's own error code would mask the child's.
	code := app.Execute(context.Background(), []string{
		"mcp-shim", "--server", "demo", "--audit-dir", t.TempDir(), "--no-sandbox", "--", shell(t), path,
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
