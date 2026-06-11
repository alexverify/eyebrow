// Command agentguard is the single static binary entrypoint. It keeps main
// thin: build an App, wire signal-based cancellation, and hand control to the
// CLI adapter. All behavior lives in internal packages so it can be tested
// without spawning a process.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexverify/agentguard/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cli.New(os.Stdout, os.Stderr)
	os.Exit(app.Execute(ctx, os.Args[1:]))
}
