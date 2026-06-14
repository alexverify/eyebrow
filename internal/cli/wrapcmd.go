package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/assay/internal/adapters/mcpconfig"
	"github.com/alexverify/assay/internal/sandbox"
)

// runWrap installs (or reports) MCP interposition for a tool's stdio servers.
// Claude Code only in this slice; the flag exists so adding tools later
// doesn't change the interface.
func (a *App) runWrap(ctx context.Context, args []string) int {
	fs := a.flagSet("wrap")
	tool := fs.String("tool", "claude-code", "tool whose MCP config to wrap (claude-code only for now)")
	path := fs.String("path", ".", "project root")
	global := fs.Bool("global", false, "wrap the user-level (~/.claude.json) config instead of a project")
	status := fs.Bool("status", false, "show wrap state instead of changing anything")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	cfg, code := a.loadMCPConfig(*tool, *path, *global, "wrap")
	if cfg == nil {
		return code
	}
	if *status {
		return a.printWrapStatus(cfg)
	}

	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin = "assay" // fall back to PATH resolution by the AI tool
	}
	n := cfg.Wrap(bin)
	if n > 0 {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(a.Stderr, "wrap: %v\n", err)
			return ExitError
		}
	}
	fmt.Fprintf(a.Stdout, "wrapped %d server(s); tool calls will be audited to %s\n", n, a.auditDir())
	if n > 0 && sandbox.Select(sandbox.Profile{}).Name() == "none" {
		fmt.Fprintf(a.Stdout, "warning: no OS sandbox on this platform — servers run unconfined and "+
			"egress-proxy routing is cooperative (a server could bypass it). "+
			"Tool-policy enforcement and auditing still apply.\n")
	}
	return ExitOK
}

// runUnwrap restores the original MCP config.
func (a *App) runUnwrap(ctx context.Context, args []string) int {
	fs := a.flagSet("unwrap")
	tool := fs.String("tool", "claude-code", "tool whose MCP config to restore")
	path := fs.String("path", ".", "project root")
	global := fs.Bool("global", false, "unwrap the user-level (~/.claude.json) config instead of a project")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	cfg, code := a.loadMCPConfig(*tool, *path, *global, "unwrap")
	if cfg == nil {
		return code
	}
	n := cfg.Unwrap()
	if n > 0 {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(a.Stderr, "unwrap: %v\n", err)
			return ExitError
		}
	}
	fmt.Fprintf(a.Stdout, "unwrapped %d server(s)\n", n)
	return ExitOK
}

// loadMCPConfig validates the tool and loads its MCP config — the user-level
// ~/.claude.json when global, else the project's .mcp.json. On failure it
// reports and returns a nil config with the exit code to use.
func (a *App) loadMCPConfig(tool, path string, global bool, cmd string) (*mcpconfig.Config, int) {
	if tool != "claude-code" {
		fmt.Fprintf(a.Stderr, "%s: tool %q not supported yet (only claude-code)\n", cmd, tool)
		return nil, ExitUsage
	}
	cfgPath := filepath.Join(path, ".mcp.json")
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
			return nil, ExitError
		}
		cfgPath = filepath.Join(home, ".claude.json")
	}
	cfg, err := mcpconfig.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
		return nil, ExitError
	}
	return cfg, ExitOK
}

func (a *App) printWrapStatus(cfg *mcpconfig.Config) int {
	for _, s := range cfg.Servers() {
		switch {
		case s.Remote:
			fmt.Fprintf(a.Stdout, "  %-20s remote (not wrappable yet)\n", s.Name)
		case s.Wrapped:
			fmt.Fprintf(a.Stdout, "  %-20s wrapped → %s\n", s.Name, strings.Join(append([]string{s.Command}, s.Args...), " "))
		default:
			fmt.Fprintf(a.Stdout, "  %-20s not wrapped (%s)\n", s.Name, s.Command)
		}
	}
	return ExitOK
}
