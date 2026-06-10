// Package cli is the driving adapter: it parses arguments, wires the concrete
// adapters into the application services (the composition root), and maps
// outcomes to process exit codes. It depends on adapters and app packages, but
// nothing depends on it.
package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/agentguard/agentguard/internal/adapters/analyze"
	"github.com/agentguard/agentguard/internal/adapters/discover"
	"github.com/agentguard/agentguard/internal/adapters/hash"
	"github.com/agentguard/agentguard/internal/adapters/lockstore"
	"github.com/agentguard/agentguard/internal/adapters/report"
	"github.com/agentguard/agentguard/internal/adapters/resolve"
	"github.com/agentguard/agentguard/internal/app/ports"
	"github.com/agentguard/agentguard/internal/app/scan"
	"github.com/agentguard/agentguard/internal/app/verify"
	"github.com/agentguard/agentguard/internal/buildinfo"
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
	Stdout io.Writer
	Stderr io.Writer
	Clock  ports.Clock
}

// New constructs an App with the wall clock.
func New(stdout, stderr io.Writer) *App {
	return &App{Stdout: stdout, Stderr: stderr, Clock: ports.ClockFunc(time.Now)}
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

// scanService assembles the scan use case from concrete adapters.
func (a *App) scanService(jsonOut bool) *scan.Service {
	return scan.New(scan.Deps{
		Discoverer: discover.Default(),
		Resolver:   resolve.NewRouter(),
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyze.NewNative(), analyze.NewSemgrep("rules")),
		Lock:       lockstore.New(),
		Reporter:   reporter(jsonOut),
		Clock:      a.Clock,
	})
}

// verifyService assembles the verify use case. It reuses a scan service purely
// as the current-state builder (only Build is called, never Run).
func (a *App) verifyService(jsonOut bool) *verify.Service {
	return verify.New(verify.Deps{
		Builder:  a.scanService(jsonOut),
		Lock:     lockstore.New(),
		Reporter: reporter(jsonOut),
	})
}
