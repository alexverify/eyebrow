package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/alexverify/assay/internal/adapters/auditlog"
	"github.com/alexverify/assay/internal/adapters/lockstore"
	"github.com/alexverify/assay/internal/adapters/policystore"
	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/dashboard"
	"github.com/alexverify/assay/internal/domain/audit"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/policy"
)

// runDashboard serves the local, read-only web dashboard on loopback. It reads
// what this machine already produces — the live inventory, drift against the
// committed lockfile, and the shim's audit log.
func (a *App) runDashboard(ctx context.Context, args []string) int {
	fs := a.flagSet("dashboard")
	c := bindCommon(fs)
	addr := fs.String("addr", "127.0.0.1:7113", "loopback address to listen on")
	auditDir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	policyPath := fs.String("policy", "assay.policy.json", "policy file the editor reads and writes")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	scopes := a.scopes(*c.path, *c.global)
	builder := a.scanService(false, *c.rules)
	store := lockstore.New()
	// The keyring (committed trusted-keys + personal) verifies approval
	// signatures so the dashboard's "verified" status is cryptographically real.
	verifier, _ := a.lockfileVerifier("assay.trustedkeys")

	srv := dashboard.New(dashboard.Deps{
		Inventory: func(ctx context.Context) (lockfile.Lockfile, error) {
			return builder.Build(ctx, scopes)
		},
		Locked: func(ctx context.Context) (lockfile.Lockfile, error) {
			lf, err := store.Read(ctx, *c.lockfile)
			if errors.Is(err, ports.ErrNoLockfile) {
				return lockfile.Lockfile{}, nil // no lockfile yet → no drift baseline
			}
			return lf, err
		},
		Audit: func(f auditlog.Filter) ([]audit.Event, error) {
			return auditlog.Read(*auditDir, f)
		},
		ApprovalVerifier: asApprovalVerifier(verifier),
		Mutate: func(ctx context.Context, fn func(lf *lockfile.Lockfile) error) error {
			lf, err := store.Read(ctx, *c.lockfile)
			if err != nil {
				return err
			}
			if err := fn(&lf); err != nil {
				return err
			}
			return store.Write(ctx, *c.lockfile, lf)
		},
		Policy: func(context.Context) (policy.Policy, error) {
			p, _, err := policystore.Load(*policyPath)
			return p, err
		},
		MutatePolicy: func(_ context.Context, fn func(p *policy.Policy) error) error {
			p, _, err := policystore.Load(*policyPath)
			if err != nil {
				return err
			}
			if err := fn(&p); err != nil {
				return err
			}
			return policystore.Save(*policyPath, p)
		},
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(a.Stderr, "dashboard: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "assay dashboard on http://%s  (ctrl-c to stop)\n", ln.Addr())
	fmt.Fprintf(a.Stdout, "write token: %s\n", srv.Token())

	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		httpSrv.Close()
	}()
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(a.Stderr, "dashboard: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// asApprovalVerifier adapts the lockfile verifier (the keyring, which also
// verifies approvals) to the approval-verifier port, or nil if unavailable.
func asApprovalVerifier(v ports.LockfileVerifier) ports.ApprovalVerifier {
	if av, ok := v.(ports.ApprovalVerifier); ok {
		return av
	}
	return nil
}
