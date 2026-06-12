// Package cli is the driving adapter: it parses arguments, wires the concrete
// adapters into the application services (the composition root), and maps
// outcomes to process exit codes. It depends on adapters and app packages, but
// nothing depends on it.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/alexverify/agentguard/internal/adapters/analyze"
	"github.com/alexverify/agentguard/internal/adapters/discover"
	"github.com/alexverify/agentguard/internal/adapters/hash"
	"github.com/alexverify/agentguard/internal/adapters/lockstore"
	"github.com/alexverify/agentguard/internal/adapters/report"
	"github.com/alexverify/agentguard/internal/adapters/resolve"
	"github.com/alexverify/agentguard/internal/adapters/sign"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/app/scan"
	"github.com/alexverify/agentguard/internal/app/verify"
	"github.com/alexverify/agentguard/internal/buildinfo"
)

// Exit codes form a stable contract for CI consumers.
const (
	ExitOK    = 0 // success, no drift
	ExitDrift = 1 // drift detected or findings over threshold (verify)
	ExitUsage = 2 // bad invocation
	ExitError = 3 // internal/IO error
)

// App holds the IO streams and clock for one CLI invocation.
type App struct {
	Stdin  io.Reader // used only by mcp-shim, which relays it to the wrapped server
	Stdout io.Writer
	Stderr io.Writer
	Clock  ports.Clock
}

// New constructs an App with the wall clock and the process stdin.
func New(stdout, stderr io.Writer) *App {
	return &App{Stdin: os.Stdin, Stdout: stdout, Stderr: stderr, Clock: ports.ClockFunc(time.Now)}
}

// Execute dispatches a subcommand and returns a process exit code.
func (a *App) Execute(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.usage()
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return a.runScan(ctx, rest)
	case "verify":
		return a.runVerify(ctx, rest)
	case "diff":
		return a.runDiff(ctx, rest)
	case "list":
		return a.runList(ctx, rest)
	case "approve":
		return a.runApprove(ctx, rest)
	case "sign":
		return a.runSign(ctx, rest)
	case "key":
		return a.runKey(ctx, rest)
	case "wrap":
		return a.runWrap(ctx, rest)
	case "unwrap":
		return a.runUnwrap(ctx, rest)
	case "audit":
		return a.runAudit(ctx, rest)
	case "mcp-shim":
		return a.runMCPShim(ctx, rest)
	case "version", "-v", "--version":
		fmt.Fprintln(a.Stdout, buildinfo.UserAgent())
		return ExitOK
	case "help", "-h", "--help":
		a.usage()
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q\n\n", cmd)
		a.usage()
		return ExitUsage
	}
}

func (a *App) usage() {
	fmt.Fprintf(a.Stderr, `%s — supply-chain integrity for AI coding tools

Usage:
  agentguard <command> [flags]

Commands:
  scan      Discover, resolve, hash, and analyze artifacts; write the lockfile
  verify    Recompute and diff against the lockfile (rug-pull detector)
  diff      Show what changed since the last lockfile (informational)
  list      Print the current inventory across tools
  approve   Mark artifact(s) as approved in the lockfile
  sign      Sign the lockfile with the local key
  key       Manage signing identity (show) and trusted keys (trust)
  wrap      Route a tool's MCP servers through the auditing shim (--status to inspect)
  unwrap    Restore the original MCP config
  audit     Summarize or list the MCP shim's audit log
  version   Print the version
  help      Show this help

Run "agentguard <command> -h" for command-specific flags.
`, buildinfo.Name)
}

// scopes builds the scan scopes from the common flags.
func (a *App) scopes(path string, global bool) []ports.Scope {
	var sc []ports.Scope
	if global {
		sc = append(sc, ports.Scope{Kind: "global"})
	}
	sc = append(sc, ports.Scope{Kind: "project", Path: path})
	return sc
}

func reporter(jsonOut bool) ports.Reporter {
	if jsonOut {
		return report.JSON{}
	}
	return report.Text{}
}

// scanService assembles the scan use case from concrete adapters. rulesDir
// points the optional Semgrep accelerator at a rules pack; an absent dir is a
// silent no-op (the native matchers are authoritative).
func (a *App) scanService(jsonOut bool, rulesDir string) *scan.Service {
	return scan.New(scan.Deps{
		Discoverer: discover.Default(),
		Resolver:   resolve.NewRouter(),
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyze.NewNative(), analyze.NewSemgrep(rulesDir)),
		Lock:       lockstore.New(),
		Reporter:   reporter(jsonOut),
		Clock:      a.Clock,
	})
}

// verifyService assembles the verify use case. It reuses a scan service purely
// as the current-state builder (only Build is called, never Run). The verifier
// may be nil when the caller never applies a signature policy (diff).
func (a *App) verifyService(jsonOut bool, rulesDir string, verifier ports.LockfileVerifier) *verify.Service {
	return verify.New(verify.Deps{
		Builder:  a.scanService(jsonOut, rulesDir),
		Lock:     lockstore.New(),
		Reporter: reporter(jsonOut),
		Verifier: verifier,
	})
}

// auditDir is the default audit-log location.
func (a *App) auditDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "audit")
}

// keyPath is the default local signing-key location.
func (a *App) keyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "key")
}

// trustedKeysPath is the user-level trusted-keys registry.
func (a *App) trustedKeysPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentguard", "trusted_keys")
}

// lockfileVerifier builds the trust set used to check lockfile signatures: the
// committed project registry plus the user registry. Only when neither declares
// any key does the local signing key count as trusted, so a single user
// verifies their own signatures with zero ceremony while a committed registry
// stays authoritative (local verify --ci behaves exactly like CI).
func (a *App) lockfileVerifier(projectRegistry string) (ports.LockfileVerifier, error) {
	kr, err := sign.LoadKeyring(projectRegistry, a.trustedKeysPath())
	if err != nil {
		return nil, err
	}
	if kr.Len() == 0 {
		if s, err := sign.Load(a.keyPath()); err == nil {
			if err := kr.AddBase64(s.PublicKeyBase64()); err != nil {
				return nil, err
			}
		}
	}
	return kr, nil
}
