package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/adapters/policystore"
	"github.com/alexverify/eyebrow/internal/app/shim"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/proxy"
	"github.com/alexverify/eyebrow/internal/sandbox"
)

// runMCPShim is the hidden command `wrap` installs into MCP configs:
//
//	eyebrow mcp-shim --server <name> -- <original command and args>
//
// It spawns the real server, relays JSON-RPC transparently, audits tool
// calls, and exits with the child's exit code so the AI tool can't tell the
// difference.
func (a *App) runMCPShim(ctx context.Context, args []string) int {
	fs := a.flagSet("mcp-shim")
	server := fs.String("server", "", "name of the wrapped MCP server (for the audit log)")
	auditDir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	policyPath := fs.String("policy", "eyebrow.policy.json", "policy file with mcp tool rules (cwd is the project root)")
	noProxy := fs.Bool("no-egress-proxy", false, "do not route the server's HTTP(S) traffic through the auditing egress proxy")
	noSandbox := fs.Bool("no-sandbox", false, "do not confine the server with the OS sandbox")
	workspace := fs.String("workspace", "", "directory the sandboxed server may read/write (default: current dir)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	argv := fs.Args()
	if *server == "" || len(argv) == 0 {
		fmt.Fprintln(a.Stderr, "mcp-shim: usage: eyebrow mcp-shim --server <name> -- <command> [args...]")
		return ExitUsage
	}

	// A missing policy file means "allow everything" (the shim stays
	// observe-only); a malformed one fails loudly — silently dropping the
	// team's rules would be worse than refusing to start.
	pol, _, err := policystore.Load(*policyPath)
	if err != nil {
		return a.fail("mcp-shim", err)
	}

	sink := auditlog.New(*auditDir)
	session := newSessionID()

	// Start the egress proxy first: its address is the only network endpoint
	// the sandbox profile will permit, so the proxy must exist before the
	// profile is built. Cooperative env injection alone (no sandbox) is what
	// the proxy relied on before this slice.
	var childEnv []string
	var proxyAddr string
	if !*noProxy {
		egress := proxy.New(
			proxy.Deps{Audit: sink, Clock: a.Clock},
			proxy.Options{Server: *server, Session: session, Policy: pol},
		)
		addr, perr := egress.Start()
		if perr != nil {
			fmt.Fprintf(a.Stderr, "mcp-shim: egress proxy disabled: %v\n", perr)
		} else {
			defer egress.Close()
			proxyAddr = addr
			childEnv = withProxyEnv(os.Environ(), "http://"+addr)
		}
	}

	// Confine the server: rewrite argv to run under the OS sandbox, allowing
	// only the workspace and the proxy port. An unavailable backend is the
	// identity transform, so this degrades to the prior (cooperative) behavior.
	sandboxName := "none"
	if !*noSandbox {
		ws := *workspace
		if ws == "" {
			ws, _ = os.Getwd()
		}
		backend := sandbox.Select(sandbox.Profile{
			Workspace:  resolvePath(ws),
			ProxyAddr:  proxyAddr,
			DenyPaths:  resolvePaths(sensitiveDenyPaths()),
			WritePaths: resolvePaths([]string{os.TempDir()}),
		})
		sandboxName = backend.Name()
		wrapped, werr := backend.Wrap(argv)
		if werr != nil {
			return a.fail("mcp-shim", werr)
		}
		argv = wrapped
	}

	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
	child.Stderr = a.Stderr // the server's stderr stays visible to the tool
	child.Env = childEnv    // nil keeps the parent environment

	serverIn, err := child.StdinPipe()
	if err != nil {
		return a.fail("mcp-shim", err)
	}
	serverOut, err := child.StdoutPipe()
	if err != nil {
		return a.fail("mcp-shim", err)
	}
	if err := child.Start(); err != nil {
		fmt.Fprintf(a.Stderr, "mcp-shim: start %s: %v\n", argv[0], err)
		return ExitError
	}

	// Forward termination signals so the tool can stop the real server
	// through the shim.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			_ = child.Process.Signal(s)
		}
	}()

	relay := shim.New(shim.Deps{Audit: sink, Clock: a.Clock})
	_ = relay.Run(ctx, shim.Options{Server: *server, Session: session, Policy: pol, Sandbox: sandboxName},
		a.Stdin, a.Stdout, serverIn, serverOut)

	exitCode, detail := waitChild(child)
	_ = sink.Emit(ctx, audit.Event{
		At: a.Clock.Now(), Session: session, Server: *server,
		Kind: audit.KindServerExit, Detail: detail,
	})
	return exitCode
}

// waitChild reaps the server process, mapping its end to an exit code and a
// human-readable detail for the audit log.
func waitChild(child *exec.Cmd) (int, string) {
	err := child.Wait()
	if err == nil {
		return 0, "exit status 0"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), ee.String()
	}
	return ExitError, err.Error()
}

func newSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// withProxyEnv points the child's HTTP stack at the egress proxy. It drops any
// pre-existing *_PROXY entry first: env lookup is case-insensitive on Windows,
// so an empty HTTP_PROXY already in the environment would otherwise shadow the
// value we set. Both upper- and lower-case forms are set for tools that read
// either.
func withProxyEnv(base []string, proxyURL string) []string {
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		lower := strings.ToLower(kv)
		if strings.HasPrefix(lower, "http_proxy=") || strings.HasPrefix(lower, "https_proxy=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL, "https_proxy="+proxyURL)
}

// resolvePath returns the symlink-resolved path so sandbox profiles match the
// real path (on macOS /tmp and /var are symlinks into /private). Unresolvable
// paths pass through unchanged.
func resolvePath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func resolvePaths(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, resolvePath(p))
	}
	return out
}

// sensitiveDenyPaths are credential/secret locations the sandbox blocks
// outright, even though they sit outside the workspace and would already be
// unreadable — defense in depth and an explicit, auditable list.
func sensitiveDenyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, rel := range []string{".ssh", ".aws", ".config/solana", ".config/gcloud", ".gnupg", ".kube", ".docker/config.json", ".npmrc"} {
		out = append(out, filepath.Join(home, rel))
	}
	return out
}
