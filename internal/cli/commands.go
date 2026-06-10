package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/user"
	"strings"

	"github.com/alexverify/agentguard/internal/adapters/lockstore"
	"github.com/alexverify/agentguard/internal/adapters/policystore"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/app/scan"
	"github.com/alexverify/agentguard/internal/app/verify"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// commonFlags are shared by the read pipeline commands.
type commonFlags struct {
	path     *string
	global   *bool
	lockfile *string
	json     *bool
}

func bindCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		path:     fs.String("path", ".", "project root to scan"),
		global:   fs.Bool("global", false, "also include the global (user-home) scope"),
		lockfile: fs.String("lockfile", "agentlock.json", "lockfile path"),
		json:     fs.Bool("json", false, "machine-readable JSON output"),
	}
}

func (a *App) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

func (a *App) runScan(ctx context.Context, args []string) int {
	fs := a.flagSet("scan")
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	svc := a.scanService(*c.json)
	if _, err := svc.Run(ctx, scan.Options{
		Scopes:       a.scopes(*c.path, *c.global),
		LockfilePath: *c.lockfile,
	}, a.Stdout); err != nil {
		fmt.Fprintf(a.Stderr, "scan: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func (a *App) runVerify(ctx context.Context, args []string) int {
	fs := a.flagSet("verify")
	c := bindCommon(fs)
	ci := fs.Bool("ci", false, "strict mode: also apply the policy gate (severity threshold, approvals)")
	policyPath := fs.String("policy", "agentguard.policy.json", "policy file applied in --ci mode")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	pol, _, err := policystore.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "verify: %v\n", err)
		return ExitError
	}

	svc := a.verifyService(*c.json)
	res, err := svc.Run(ctx, verify.Options{
		Scopes:       a.scopes(*c.path, *c.global),
		LockfilePath: *c.lockfile,
		CI:           *ci,
		Policy:       pol,
	}, a.Stdout)
	if err != nil {
		if errors.Is(err, ports.ErrNoLockfile) {
			fmt.Fprintln(a.Stderr, "verify: no lockfile found; run 'agentguard scan' first")
			return ExitError
		}
		fmt.Fprintf(a.Stderr, "verify: %v\n", err)
		return ExitError
	}
	for _, v := range res.Policy.Violations {
		if v.Kind == "unapproved" {
			fmt.Fprintf(a.Stdout, "policy: unapproved artifact %s (%s)\n", v.Name, v.ID)
		} else {
			fmt.Fprintf(a.Stdout, "policy: %s %s %s\n", v.Severity, v.RuleID, v.Detail)
		}
	}
	if !res.OK {
		return ExitDrift
	}
	return ExitOK
}

// runDiff is verify without the failing exit code: informational only.
func (a *App) runDiff(ctx context.Context, args []string) int {
	fs := a.flagSet("diff")
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	svc := a.verifyService(*c.json)
	_, err := svc.Run(ctx, verify.Options{
		Scopes:       a.scopes(*c.path, *c.global),
		LockfilePath: *c.lockfile,
	}, a.Stdout)
	if err != nil {
		if errors.Is(err, ports.ErrNoLockfile) {
			fmt.Fprintln(a.Stderr, "diff: no lockfile found; run 'agentguard scan' first")
			return ExitError
		}
		fmt.Fprintf(a.Stderr, "diff: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func (a *App) runList(ctx context.Context, args []string) int {
	fs := a.flagSet("list")
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	svc := a.scanService(*c.json)
	lf, err := svc.Build(ctx, a.scopes(*c.path, *c.global))
	if err != nil {
		fmt.Fprintf(a.Stderr, "list: %v\n", err)
		return ExitError
	}
	if err := reporter(*c.json).List(a.Stdout, lf); err != nil {
		fmt.Fprintf(a.Stderr, "list: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func (a *App) runApprove(ctx context.Context, args []string) int {
	fs := a.flagSet("approve")
	lock := fs.String("lockfile", "agentlock.json", "lockfile path")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	ids := fs.Args()
	if len(ids) == 0 {
		fmt.Fprintln(a.Stderr, "approve: provide one or more artifact IDs (prefixes accepted)")
		return ExitUsage
	}

	store := lockstore.New()
	lf, err := store.Read(ctx, *lock)
	if err != nil {
		if errors.Is(err, ports.ErrNoLockfile) {
			fmt.Fprintln(a.Stderr, "approve: no lockfile found; run 'agentguard scan' first")
			return ExitError
		}
		fmt.Fprintf(a.Stderr, "approve: %v\n", err)
		return ExitError
	}

	now := a.Clock.Now().UTC()
	who := currentUser()
	matched := 0
	for i := range lf.Artifacts {
		for _, id := range ids {
			if strings.HasPrefix(lf.Artifacts[i].ID, id) {
				lf.Artifacts[i].Approval = &lockfile.Approval{Status: "approved", By: who, At: now}
				matched++
				break
			}
		}
	}
	if matched == 0 {
		fmt.Fprintf(a.Stderr, "approve: no artifact matched %v\n", ids)
		return ExitError
	}
	if err := store.Write(ctx, *lock, lf); err != nil {
		fmt.Fprintf(a.Stderr, "approve: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "approved %d artifact(s)\n", matched)
	return ExitOK
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
