package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/alexverify/assay/internal/adapters/fleetstore"
	"github.com/alexverify/assay/internal/adapters/lockstore"
	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/dashboard"
	"github.com/alexverify/assay/internal/domain/fleet"
	"github.com/alexverify/assay/internal/domain/lockfile"
	"github.com/alexverify/assay/internal/domain/posture"
)

// runFleet exports this machine's snapshot or prints the team blast-radius (G1).
//
//	assay fleet export   write a counts-and-hashes snapshot to the shared dir
//	assay fleet          aggregate every snapshot in the dir and print exposure
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
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	switch sub {
	case "export":
		return a.fleetExport(ctx, c, *dir, *owner)
	case "", "show", "status":
		return a.fleetShow(*dir)
	default:
		fmt.Fprintf(a.Stderr, "fleet: unknown subcommand %q (want: export | show)\n", sub)
		return ExitUsage
	}
}

// fleetExport builds this machine's snapshot from the live inventory joined with
// the lockfile (reusing the dashboard's drift/verdict interpretation) and writes
// it to the shared directory.
func (a *App) fleetExport(ctx context.Context, c commonFlags, dir, owner string) int {
	current, err := a.scanService(*c.json, *c.rules).Build(ctx, a.scopes(*c.path, *c.global))
	if err != nil {
		fmt.Fprintf(a.Stderr, "fleet: %v\n", err)
		return ExitError
	}
	locked, err := lockstore.New().Read(ctx, *c.lockfile)
	if err != nil && !errors.Is(err, ports.ErrNoLockfile) {
		fmt.Fprintf(a.Stderr, "fleet: %v\n", err)
		return ExitError
	}

	if owner == "" {
		owner = hostname()
	}
	snap := fleet.Snapshot{
		Owner:       owner,
		GeneratedAt: a.Clock.Now().UTC(),
		Artifacts:   snapshotArtifacts(current, locked),
	}
	if err := fleetstore.Write(dir, snap); err != nil {
		fmt.Fprintf(a.Stderr, "fleet: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "wrote fleet snapshot for %q: %d artifacts → %s\n", owner, len(snap.Artifacts), dir)
	return ExitOK
}

// fleetShow aggregates every snapshot under dir and prints the blast radius.
func (a *App) fleetShow(dir string) int {
	snaps, err := fleetstore.Read(dir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "fleet: %v\n", err)
		return ExitError
	}
	if len(snaps) == 0 {
		fmt.Fprintf(a.Stdout, "no fleet snapshots in %s — run `assay fleet export` on each machine\n", dir)
		return ExitOK
	}
	r := fleet.Aggregate(snaps)
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
	return ExitOK
}

// snapshotArtifacts maps the dashboard's assembled view onto the content-free
// fleet record, reusing BuildScan so drift and verdict match the dashboard
// exactly. Usage telemetry is not needed for the snapshot, so it is omitted.
func snapshotArtifacts(current, locked lockfile.Lockfile) []fleet.Artifact {
	scan := dashboard.BuildScan(current, locked, posture.ApprovedSet(locked), nil)
	out := make([]fleet.Artifact, 0, len(scan))
	for _, d := range scan {
		out = append(out, fleet.Artifact{
			ID:      d.ID,
			Name:    d.Name,
			Kind:    d.Kind,
			Hash:    d.Hash,
			Drift:   d.Drift,
			Verdict: d.Verdict,
		})
	}
	return out
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
