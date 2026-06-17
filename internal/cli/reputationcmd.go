package cli

import (
	"context"
	"fmt"

	"github.com/alexverify/assay/internal/client"
)

// runReputation looks up one or more content hashes against the control plane's
// reputation corpus (H3b) and prints each one's truster count and grade. It
// sends only the hashes given — nothing about their content. Opt-in: requires a
// server.
func (a *App) runReputation(ctx context.Context, args []string) int {
	fs := a.flagSet("reputation")
	server := fs.String("server", envOr("ASSAY_SERVER", ""), "control-plane URL")
	token := fs.String("token", envOr("ASSAY_TOKEN", ""), "machine token for the control plane")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *server == "" {
		fmt.Fprintln(a.Stderr, "reputation: set --server (or ASSAY_SERVER) to a control-plane URL")
		return ExitUsage
	}
	hashes := fs.Args()
	if len(hashes) == 0 {
		fmt.Fprintln(a.Stderr, "reputation: provide one or more content hashes to look up")
		return ExitUsage
	}

	src, err := client.New(*server, *token).Reputation(ctx, hashes)
	if err != nil {
		fmt.Fprintf(a.Stderr, "reputation: %v\n", err)
		return ExitError
	}
	if *jsonOut {
		return a.emitJSON(src)
	}
	for _, h := range hashes {
		if sig, ok := src.Lookup(h); ok {
			fmt.Fprintf(a.Stdout, "%-20s %s (trusted by %d)\n", h, sig.Grade(), sig.Trusters)
		} else {
			fmt.Fprintf(a.Stdout, "%-20s unknown\n", h)
		}
	}
	return ExitOK
}
