// Package cli is the driving adapter: it parses arguments, wires the concrete
// adapters into the application services (the composition root), and maps
// outcomes to process exit codes. It depends on adapters and app packages, but
// nothing depends on it.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/analyze"
	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/adapters/hash"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/report"
	"github.com/alexverify/eyebrow/internal/adapters/resolve"
	"github.com/alexverify/eyebrow/internal/adapters/sign"
	"github.com/alexverify/eyebrow/internal/adapters/snapshotstore"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/app/verify"
	"github.com/alexverify/eyebrow/internal/buildinfo"
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
	case "digest":
		return a.runDigest(ctx, rest)
	case "sbom":
		return a.runSBOM(ctx, rest)
	case "list":
		return a.runList(ctx, rest)
	case "approve":
		return a.runApprove(ctx, rest)
	case "quarantine":
		return a.runQuarantine(ctx, rest)
	case "freeze":
		return a.runFreeze(ctx, rest)
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
	case "record-use":
		return a.runRecordUse(ctx, rest)
	case "install-hooks":
		return a.runInstallHooks(ctx, rest)
	case "dashboard":
		return a.runDashboard(ctx, rest)
	case "fleet":
		return a.runFleet(ctx, rest)
	case "serve":
		return a.runServe(ctx, rest)
	case "alerts":
		return a.runAlerts(ctx, rest)
	case "reputation":
		return a.runReputation(ctx, rest)
	case "mcp-shim":
		return a.runMCPShim(ctx, rest)
	case "completion":
		return a.runCompletion(rest)
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
  eyebrow <command> [flags]

Commands:
  scan      Discover, resolve, hash, and analyze artifacts; write the lockfile
  verify    Recompute and diff against the lockfile (rug-pull detector)
  diff      Show what changed since the last lockfile (informational)
  digest    Summarize what changed since the lockfile (what to review)
  sbom      Export the lockfile as a CycloneDX SBOM (--o file)
  list      Print the current inventory across tools
  approve   Mark artifact(s) as approved in the lockfile
  quarantine Disable artifact(s) pending review (--remove to lift)
  freeze    Pin artifact(s); any later drift fails the gate (--remove to lift)
  sign      Sign the lockfile with the local key
  key       Manage signing identity (show) and trusted keys (trust)
  wrap      Route a tool's MCP servers through the auditing shim (--status to inspect)
  unwrap    Restore the original MCP config
  audit     Summarize or list the MCP shim's audit log (audit push uploads it to a server)
  alerts    List team alerts from the control plane (drift, quarantine, blocked egress)
  reputation Look up content hashes in the reputation corpus (reputation export builds one from approvals)
  record-use   Record an artifact activation (called by a host-tool hook)
  install-hooks Install host-tool hooks that feed usage telemetry (--status, --uninstall)
  dashboard Serve a local read-only web dashboard (loopback)
  fleet     Export/push this machine's snapshot, print the team blast-radius, or verify (CI gate)
  serve     Run the self-hostable team control plane (opt-in; ingests snapshots)
  completion Print a shell completion script (bash|zsh|fish)
  version   Print the version
  help      Show this help

Run "eyebrow <command> -h" for command-specific flags.
`, buildinfo.Name)
}

// fail prints a command-scoped error to stderr and returns the internal-error
// exit code, so every command reports failures the same way ("<cmd>: <err>").
// The "no lockfile yet" case maps to the actionable hint the read commands
// share, replacing the per-command copy of that branch.
func (a *App) fail(cmd string, err error) int {
	if errors.Is(err, ports.ErrNoLockfile) {
		fmt.Fprintf(a.Stderr, "%s: no lockfile found; run 'eyebrow scan' first\n", cmd)
	} else {
		fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
	}
	return ExitError
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

// capturingScanService is the scan service wired to also capture file bytes into
// the project's blob store, backing the dashboard's line-level drift diff (H1b).
// Only `scan` (recording the baseline) and the dashboard's live build use it; the
// read-only commands (verify/diff/digest/list) do not write baselines.
func (a *App) capturingScanService(jsonOut bool, rulesDir, projectPath string) *scan.Service {
	return scan.New(scan.Deps{
		Discoverer: discover.Default(),
		Resolver:   resolve.NewRouter(),
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyze.NewNative(), analyze.NewSemgrep(rulesDir)),
		Lock:       lockstore.New(),
		Reporter:   reporter(jsonOut),
		Clock:      a.Clock,
		Snapshots:  snapshotstore.New(a.snapshotDir(projectPath)),
	})
}

// verifyService assembles the verify use case. It reuses a scan service purely
// as the current-state builder (only Build is called, never Run). The verifier
// may be nil when the caller never applies a signature policy (diff).
func (a *App) verifyService(jsonOut bool, rulesDir string, verifier ports.LockfileVerifier) *verify.Service {
	d := verify.Deps{
		Builder:  a.scanService(jsonOut, rulesDir),
		Lock:     lockstore.New(),
		Reporter: reporter(jsonOut),
		Verifier: verifier,
	}
	// The keyring satisfies both verifier ports; reuse it for approvals.
	if av, ok := verifier.(ports.ApprovalVerifier); ok {
		d.ApprovalVerifier = av
	}
	return verify.New(d)
}

// auditDir is the default audit-log location.
func (a *App) auditDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".eyebrow", "audit")
}

// snapshotDir is the content-addressed store of approved file bytes backing the
// dashboard's line-level drift diff (H1b). It lives under the scanned project so
// baselines stay project-local (and gitignored) — a local cache, not part of the
// signed lockfile.
func (a *App) snapshotDir(projectPath string) string {
	return filepath.Join(projectPath, ".eyebrow", "snapshots")
}

// fleetDir is the default fleet-snapshot directory: a project-local, shared
// path meant to be committed ("git is the backend"), so the whole team's
// snapshots aggregate without any server.
func (a *App) fleetDir() string {
	return filepath.Join(".eyebrow", "fleet")
}

// historyPath is the default posture-trend history file.
func (a *App) historyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".eyebrow", "history.jsonl")
}

// keyPath is the default local signing-key location.
func (a *App) keyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".eyebrow", "key")
}

// trustedKeysPath is the user-level trusted-keys registry.
func (a *App) trustedKeysPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".eyebrow", "trusted_keys")
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
