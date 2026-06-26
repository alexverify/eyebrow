package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/adapters/fleetstore"
	"github.com/alexverify/eyebrow/internal/adapters/historystore"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/policystore"
	"github.com/alexverify/eyebrow/internal/adapters/repstore"
	"github.com/alexverify/eyebrow/internal/adapters/sign"
	"github.com/alexverify/eyebrow/internal/adapters/snapshotstore"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/dashboard"
	"github.com/alexverify/eyebrow/internal/domain/alert"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
	"github.com/alexverify/eyebrow/internal/domain/posture"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

// runDashboard serves the local, read-only web dashboard on loopback. It reads
// what this machine already produces — the live inventory, drift against the
// committed lockfile, and the shim's audit log.
func (a *App) runDashboard(ctx context.Context, args []string) int {
	fs := a.flagSet("dashboard")
	c := bindCommon(fs)
	addr := fs.String("addr", "127.0.0.1:7113", "loopback address to listen on")
	auditDir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	policyPath := fs.String("policy", "eyebrow.policy.json", "policy file the editor reads and writes")
	historyPath := fs.String("history", a.historyPath(), "posture-trend history file")
	fleetDir := fs.String("fleet-dir", a.fleetDir(), "shared fleet-snapshot directory (blast radius)")
	reputationPath := fs.String("reputation", "eyebrow.reputation.json", "opt-in community reputation corpus (hash-keyed; absent = no signal)")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL (opt-in: the Fleet and Alerts tabs read hosted org data)")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	reputationServer := fs.String("reputation-server", "", "control-plane URL for a live hash-only reputation lookup (defaults to --server)")
	reputationToken := fs.String("reputation-token", "", "machine token for the reputation lookup (defaults to --token)")
	snapshotDir := fs.String("snapshot-dir", "", "content-addressed store of approved file bytes (line-level drift diff); default <path>/.eyebrow/snapshots")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *reputationServer == "" {
		*reputationServer, *reputationToken = *server, *token
	}
	if *snapshotDir == "" {
		*snapshotDir = a.snapshotDir(*c.path)
	}

	scopes := a.scopes(*c.path, *c.global)
	builder := a.capturingScanService(false, *c.rules, *c.path)
	store := lockstore.New()
	// The keyring (committed trusted-keys + personal) verifies approval
	// signatures so the dashboard's "verified" status is cryptographically real.
	verifier, _ := a.lockfileVerifier("eyebrow.trustedkeys")
	// Team mode: a trusted-keys registry declares at least one key (checked
	// before the local-key self-trust fallback). Solo users (no registry) get the
	// simplified Approved / Not-approved view with no signing vocabulary.
	teamMode := false
	if reg, err := sign.LoadKeyring("eyebrow.trustedkeys", a.trustedKeysPath()); err == nil {
		teamMode = reg.Len() > 0
	}

	srv := dashboard.New(dashboard.Deps{
		TeamMode: teamMode,
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
			if errors.Is(err, ports.ErrNoLockfile) {
				lf = lockfile.Lockfile{} // no lockfile yet → account the first artifact into a fresh one
			} else if err != nil {
				return err
			}
			if err := fn(&lf); err != nil {
				return err
			}
			return store.Write(ctx, *c.lockfile, lf)
		},
		SignApproval: func(e lockfile.Entry) (string, error) {
			// Sign with the local key (minting it on first approve) so dashboard
			// approvals are Verified, not just Unsigned — the same act as
			// `eyebrow approve --sign`, on a loopback surface the user already owns.
			signer, err := sign.LoadOrCreate(a.keyPath())
			if err != nil {
				return "", err
			}
			return signer.SignApproval(e)
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
		History: func(context.Context) ([]posture.Posture, error) {
			return historystore.Read(*historyPath)
		},
		Fleet: func(ctx context.Context) (fleet.Report, error) {
			// With a control plane configured, the Fleet tab reads the org's
			// hosted blast-radius (4e); otherwise the committed local snapshots.
			if *server != "" {
				return client.New(*server, *token).Fleet(ctx)
			}
			snaps, err := fleetstore.Read(*fleetDir)
			if err != nil {
				return fleet.Report{}, err
			}
			return fleet.Aggregate(snaps), nil
		},
		Conformance: func(ctx context.Context) (fleet.Conformance, error) {
			if *server != "" {
				return client.New(*server, *token).Conformance(ctx)
			}
			snaps, err := fleetstore.Read(*fleetDir)
			if err != nil {
				return fleet.Conformance{}, err
			}
			p, _, err := policystore.Load(*policyPath)
			if err != nil {
				return fleet.Conformance{}, err
			}
			return fleet.CheckConformance(p, snaps), nil
		},
		Alerts: func(ctx context.Context) ([]alert.Alert, error) {
			// Team alerts come only from a control plane; nil when local-only.
			if *server == "" {
				return nil, nil
			}
			return client.New(*server, *token).Alerts(ctx)
		},
		Reputation: func(hashes []string) (reputation.Source, error) {
			// A live hash-only lookup when a control plane is configured (H3b);
			// otherwise the local opt-in corpus. The live lookup sends only the
			// inventory's hashes, never anything about their content.
			if *reputationServer != "" {
				return client.New(*reputationServer, *reputationToken).Reputation(context.Background(), hashes)
			}
			return repstore.Load(*reputationPath)
		},
		Blobs: snapshotstore.New(*snapshotDir).Get,
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return a.fail("dashboard", err)
	}
	fmt.Fprintf(a.Stdout, "eyebrow dashboard on http://%s  (ctrl-c to stop)\n", ln.Addr())
	fmt.Fprintf(a.Stdout, "write token: %s\n", srv.Token())

	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		httpSrv.Close()
	}()
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return a.fail("dashboard", err)
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
