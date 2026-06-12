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
	"syscall"

	"github.com/alexverify/agentguard/internal/adapters/auditlog"
	"github.com/alexverify/agentguard/internal/adapters/policystore"
	"github.com/alexverify/agentguard/internal/app/shim"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/proxy"
)

// runMCPShim is the hidden command `wrap` installs into MCP configs:
//
//	agentguard mcp-shim --server <name> -- <original command and args>
//
// It spawns the real server, relays JSON-RPC transparently, audits tool
// calls, and exits with the child's exit code so the AI tool can't tell the
// difference.
func (a *App) runMCPShim(ctx context.Context, args []string) int {
	fs := a.flagSet("mcp-shim")
	server := fs.String("server", "", "name of the wrapped MCP server (for the audit log)")
	auditDir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	policyPath := fs.String("policy", "agentguard.policy.json", "policy file with mcp tool rules (cwd is the project root)")
	noProxy := fs.Bool("no-egress-proxy", false, "do not route the server's HTTP(S) traffic through the auditing egress proxy")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	argv := fs.Args()
	if *server == "" || len(argv) == 0 {
		fmt.Fprintln(a.Stderr, "mcp-shim: usage: agentguard mcp-shim --server <name> -- <command> [args...]")
		return ExitUsage
	}

	// A missing policy file means "allow everything" (the shim stays
	// observe-only); a malformed one fails loudly — silently dropping the
	// team's rules would be worse than refusing to start.
	pol, _, err := policystore.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "mcp-shim: %v\n", err)
		return ExitError
	}

	sink := auditlog.New(*auditDir)
	session := newSessionID()

	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
	child.Stderr = a.Stderr // the server's stderr stays visible to the tool

	// Point the server's HTTP stack at the egress proxy (host rules, body
	// redaction, per-connection audit). Cooperative until the sandbox slice:
	// well-behaved HTTP libraries honor these variables.
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
			pu := "http://" + addr
			child.Env = append(os.Environ(),
				"HTTP_PROXY="+pu, "HTTPS_PROXY="+pu, "http_proxy="+pu, "https_proxy="+pu)
		}
	}
	serverIn, err := child.StdinPipe()
	if err != nil {
		fmt.Fprintf(a.Stderr, "mcp-shim: %v\n", err)
		return ExitError
	}
	serverOut, err := child.StdoutPipe()
	if err != nil {
		fmt.Fprintf(a.Stderr, "mcp-shim: %v\n", err)
		return ExitError
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
	_ = relay.Run(ctx, shim.Options{Server: *server, Session: session, Policy: pol},
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
