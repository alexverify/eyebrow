package cli

import (
	"context"
	"fmt"

	"github.com/alexverify/eyebrow/internal/client"
)

// runAlerts lists the org's team-level alerts from the control plane: drifted or
// quarantined artifacts across the fleet, and blocked egress / denied tool calls
// from ingested audit. Read-only; opt-in (requires a server).
func (a *App) runAlerts(ctx context.Context, args []string) int {
	fs := a.flagSet("alerts")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *server == "" {
		fmt.Fprintln(a.Stderr, "alerts: set --server (or EYEBROW_SERVER) to a control-plane URL")
		return ExitUsage
	}

	alerts, err := client.New(*server, *token).Alerts(ctx)
	if err != nil {
		return a.fail("alerts", err)
	}
	if *jsonOut {
		return a.emitJSON(alerts)
	}
	if len(alerts) == 0 {
		fmt.Fprintln(a.Stdout, "no alerts — the fleet is clear")
		return ExitOK
	}
	for _, al := range alerts {
		fmt.Fprintf(a.Stdout, "%-8s %-13s %-24s %s\n", al.Severity, al.Kind, al.Subject, al.Detail)
	}
	return ExitOK
}
