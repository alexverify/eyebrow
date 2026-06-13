package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/alexverify/agentguard/internal/adapters/auditlog"
	"github.com/alexverify/agentguard/internal/adapters/lockstore"
	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/dashboard"
	"github.com/alexverify/agentguard/internal/domain/audit"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

// runDashboard serves the local, read-only web dashboard on loopback. It reads
// what this machine already produces — the live inventory, drift against the
// committed lockfile, and the shim's audit log.
func (a *App) runDashboard(ctx context.Context, args []string) int {
	fs := a.flagSet("dashboard")
	c := bindCommon(fs)
	addr := fs.String("addr", "127.0.0.1:7113", "loopback address to listen on")
	auditDir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	scopes := a.scopes(*c.path, *c.global)
	builder := a.scanService(false, *c.rules)
	store := lockstore.New()

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
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(a.Stderr, "dashboard: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "agentguard dashboard on http://%s  (ctrl-c to stop)\n", ln.Addr())

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
