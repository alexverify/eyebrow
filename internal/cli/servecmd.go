package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/cpstore"
	"github.com/alexverify/eyebrow/internal/controlplane"
)

// runServe runs the self-hostable team control plane (Component 3b, slice 4a):
// it ingests content-free fleet snapshots and serves the aggregated
// blast-radius, reusing the same pure functions the local dashboard uses. It is
// opt-in infrastructure a team runs itself; the CLI never requires it.
func (a *App) runServe(ctx context.Context, args []string) int {
	fs := a.flagSet("serve")
	addr := fs.String("addr", "127.0.0.1:7140", "address to listen on (set a routable address to expose to your team)")
	storeDir := fs.String("store", a.controlplaneDir(), "snapshot store directory")
	tokensPath := fs.String("tokens", "", "JSON file mapping machine token → org (required)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	auth, err := loadTokens(*tokensPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "serve: %v\n", err)
		return ExitUsage
	}

	store := cpstore.New(*storeDir)
	svc := controlplane.NewService(store, store) // cpstore is both Store and Config
	srv := &http.Server{Addr: *addr, Handler: controlplane.NewServer(svc, auth)}

	// Shut down cleanly when the process is signalled (cmd/eyebrow cancels ctx).
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	fmt.Fprintf(a.Stdout, "eyebrow control plane on http://%s  (store: %s)\n", *addr, *storeDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return a.fail("serve", err)
	}
	return ExitOK
}

// loadTokens reads a JSON object mapping machine token → org. At least one
// mapping is required: a server with no tokens would accept nothing.
func loadTokens(path string) (controlplane.StaticAuth, error) {
	if path == "" {
		return nil, fmt.Errorf("--tokens is required (a JSON file mapping token → org)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s: no token → org mappings", path)
	}
	return controlplane.StaticAuth(m), nil
}

// controlplaneDir is the default snapshot store for `eyebrow serve`.
func (a *App) controlplaneDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".eyebrow", "controlplane")
}
