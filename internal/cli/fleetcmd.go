package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alexverify/eyebrow/internal/adapters/fleetstore"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/policystore"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/dashboard"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/posture"
)

// runFleet exports this machine's snapshot or prints the team blast-radius (G1).
//
//	eyebrow fleet export   write a counts-and-hashes snapshot to the shared dir
//	eyebrow fleet          aggregate every snapshot in the dir and print exposure
//
// A snapshot carries no code and no secrets — only artifact identity, content
// hash, and the local drift/verdict — so the fleet directory is safe to commit.
func (a *App) runFleet(ctx context.Context, args []string) int {
	sub := ""
	if len(args) > 0 && !isFlag(args[0]) {
		sub, args = args[0], args[1:]
	}
	fs := a.flagSet("fleet")
	c := bindCommon(fs)
	dir := fs.String("dir", a.fleetDir(), "shared fleet-snapshot directory")
	owner := fs.String("owner", "", "snapshot owner label (default: hostname)")
	policyPath := fs.String("policy", "eyebrow.policy.json", "policy file for conformance (show)")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL (opt-in; overrides the local dir for push/show)")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	switch sub {
	case "export":
		return a.fleetExport(ctx, c, *dir, *owner)
	case "push":
		return a.fleetPush(ctx, c, *server, *token, *owner)
	case "", "show", "status":
		if *server != "" {
			return a.fleetShowRemote(ctx, *server, *token)
		}
		return a.fleetShow(*dir, *policyPath)
	case "verify":
		return a.fleetVerify(ctx, *dir, *policyPath, *server, *token)
	default:
		fmt.Fprintf(a.Stderr, "fleet: unknown subcommand %q (want: export | push | show | verify)\n", sub)
		return ExitUsage
	}
}

// fleetVerify is the CI gate over the fleet. With a control plane configured, it
// gates the fleet that machines have pushed to the server (server-side, over the
// org policy). Otherwise it gates the local snapshot directory against the
// resolved policy. Either way it exits 1 (the stable drift/policy code) on any
// failure, over the same pure functions the dashboard uses.
func (a *App) fleetVerify(ctx context.Context, dir, policyPath, server, token string) int {
	if server != "" {
		return a.fleetVerifyRemote(ctx, server, token)
	}

	snaps, err := fleetstore.Read(dir)
	if err != nil {
		return a.fail("fleet", err)
	}
	if len(snaps) == 0 {
		fmt.Fprintf(a.Stdout, "fleet verify: no snapshots in %s — nothing to gate\n", dir)
		return ExitOK
	}

	pol, err := a.resolvePolicy(ctx, server, token, policyPath)
	if err != nil {
		return a.fail("fleet", err)
	}

	res := fleet.Gate(fleet.Aggregate(snaps), fleet.CheckConformance(pol, snaps), pol.Fleet.MaxBlastRadius)
	if res.OK {
		fmt.Fprintf(a.Stdout, "fleet verify: %d machines in policy — clear\n", len(snaps))
		return ExitOK
	}
	a.printGateFailures(res)
	return ExitDrift
}

// fleetVerifyRemote runs the gate on the control plane over the org's submitted
// snapshots, so CI gates the actual fleet without a local snapshot directory.
func (a *App) fleetVerifyRemote(ctx context.Context, server, token string) int {
	res, err := client.New(server, token).Gate(ctx)
	if err != nil {
		return a.fail("fleet", err)
	}
	if res.OK {
		fmt.Fprintln(a.Stdout, "fleet verify: control plane reports the fleet in policy — clear")
		return ExitOK
	}
	a.printGateFailures(res)
	return ExitDrift
}

// printGateFailures renders a gate failure identically for the local and remote
// paths (the explicit threshold is policy detail the local path alone holds, so
// it is omitted here for a shared, source-agnostic message).
func (a *App) printGateFailures(res fleet.GateResult) {
	for _, m := range res.NonCompliant {
		for _, v := range m.Violations {
			fmt.Fprintf(a.Stdout, "fleet: %-10s %-24s %s\n", m.Owner, v.Name, strings.Join(v.Reasons, ", "))
		}
	}
	for _, e := range res.BlastBreaches {
		fmt.Fprintf(a.Stdout, "fleet: blast radius — %s (%s) drifted/quarantined on %d machine(s) — over the fleet limit\n",
			e.Name, e.Kind, max(e.Drifted, e.Quarantine))
	}
}

// buildSnapshot assembles this machine's content-free snapshot from the live
// inventory joined with the lockfile (reusing the dashboard's drift/verdict
// interpretation). Shared by export (write to a dir) and push (send to a server).
func (a *App) buildSnapshot(ctx context.Context, c commonFlags, owner string) (fleet.Snapshot, error) {
	current, err := a.scanService(*c.json, *c.rules).Build(ctx, a.scopes(*c.path, *c.global))
	if err != nil {
		return fleet.Snapshot{}, err
	}
	locked, err := lockstore.New().Read(ctx, *c.lockfile)
	if err != nil && !errors.Is(err, ports.ErrNoLockfile) {
		return fleet.Snapshot{}, err
	}
	if owner == "" {
		owner = hostname()
	}
	return fleet.Snapshot{
		Owner:       owner,
		GeneratedAt: a.Clock.Now().UTC(),
		Artifacts:   snapshotArtifacts(current, locked),
	}, nil
}

// fleetExport writes this machine's snapshot to the shared directory ("git is
// the backend").
func (a *App) fleetExport(ctx context.Context, c commonFlags, dir, owner string) int {
	snap, err := a.buildSnapshot(ctx, c, owner)
	if err != nil {
		return a.fail("fleet", err)
	}
	if err := fleetstore.Write(dir, snap); err != nil {
		return a.fail("fleet", err)
	}
	fmt.Fprintf(a.Stdout, "wrote fleet snapshot for %q: %d artifacts → %s\n", snap.Owner, len(snap.Artifacts), dir)
	return ExitOK
}

// fleetPush submits this machine's snapshot to the control plane (the hosted
// alternative to committing it). Opt-in: it runs only when a server is set.
func (a *App) fleetPush(ctx context.Context, c commonFlags, server, token, owner string) int {
	if server == "" {
		fmt.Fprintln(a.Stderr, "fleet push: set --server (or EYEBROW_SERVER) to a control-plane URL")
		return ExitUsage
	}
	snap, err := a.buildSnapshot(ctx, c, owner)
	if err != nil {
		return a.fail("fleet", err)
	}
	if err := client.New(server, token).Submit(ctx, snap); err != nil {
		return a.fail("fleet push", err)
	}
	fmt.Fprintf(a.Stdout, "pushed fleet snapshot for %q: %d artifacts → %s\n", snap.Owner, len(snap.Artifacts), server)
	return ExitOK
}

// fleetShowRemote reads the org's aggregated blast-radius from the control plane
// and prints it with the same renderer as the local view.
func (a *App) fleetShowRemote(ctx context.Context, server, token string) int {
	rep, err := client.New(server, token).Fleet(ctx)
	if err != nil {
		return a.fail("fleet", err)
	}
	a.printFleetReport(rep)
	return ExitOK
}

// fleetShow aggregates every snapshot under dir and prints the blast radius,
// plus policy conformance when a policy file is present.
func (a *App) fleetShow(dir, policyPath string) int {
	snaps, err := fleetstore.Read(dir)
	if err != nil {
		return a.fail("fleet", err)
	}
	if len(snaps) == 0 {
		fmt.Fprintf(a.Stdout, "no fleet snapshots in %s — run `eyebrow fleet export` on each machine\n", dir)
		return ExitOK
	}
	r := fleet.Aggregate(snaps)
	a.printFleetReport(r)

	// Policy conformance (G3): who is out of compliance with the committed policy.
	if p, _, err := policystore.Load(policyPath); err == nil {
		con := fleet.CheckConformance(p, snaps)
		fmt.Fprintf(a.Stdout, "\nconformance: %d/%d machines in policy\n", con.Compliant, con.Owners)
		for _, m := range con.Machines {
			if m.Compliant {
				continue
			}
			for _, v := range m.Violations {
				fmt.Fprintf(a.Stdout, "  %-10s %-24s %s\n", m.Owner, v.Name, strings.Join(v.Reasons, ", "))
			}
		}
	}
	return ExitOK
}

// snapshotArtifacts maps the dashboard's assembled view onto the content-free
// fleet record, reusing BuildScan so drift and verdict match the dashboard
// exactly. Usage telemetry is not needed for the snapshot, so it is omitted.
func snapshotArtifacts(current, locked lockfile.Lockfile) []fleet.Artifact {
	scan := dashboard.BuildScan(current, locked, posture.ApprovedSet(locked), nil, nil)
	out := make([]fleet.Artifact, 0, len(scan))
	for _, d := range scan {
		out = append(out, fleet.Artifact{
			ID:      d.ID,
			Name:    d.Name,
			Kind:    d.Kind,
			Hash:    d.Hash,
			Source:  d.Source,
			Drift:   d.Drift,
			Verdict: d.Verdict,
		})
	}
	return out
}

// printFleetReport renders a blast-radius report, shared by the local and
// remote (control-plane) fleet views so they read identically.
func (a *App) printFleetReport(r fleet.Report) {
	fmt.Fprintf(a.Stdout, "fleet: %d machines, %d distinct artifacts\n\n", r.Owners, r.Artifacts)
	for _, e := range r.Exposures {
		risk := ""
		if e.Drifted > 0 {
			risk += fmt.Sprintf("  ⚠ drifted on %d/%d", e.Drifted, e.Installs)
		}
		if e.Quarantine > 0 {
			risk += fmt.Sprintf("  ⛔ quarantine on %d/%d", e.Quarantine, e.Installs)
		}
		if e.Variants > 1 {
			risk += fmt.Sprintf("  %d variants", e.Variants)
		}
		fmt.Fprintf(a.Stdout, "%-28s %-8s %d/%d machines%s\n", e.Name, e.Kind, e.Installs, r.Owners, risk)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

// envOr returns the environment value for key, or fallback when unset/empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
