package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/eyebrow/internal/adapters/mcpconfig"
	"github.com/alexverify/eyebrow/internal/sandbox"
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
	cfgs, code := a.mcpConfigs(*tool, *path, *global, "wrap")
	if cfgs == nil {
		return code
	}
	if *status {
		return a.printWrapStatus(cfgs)
	}

	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin = "eyebrow" // fall back to PATH resolution by the AI tool
	}
	n := 0
	for _, cfg := range cfgs {
		c := cfg.Wrap(bin)
		if c > 0 {
			if err := cfg.Save(); err != nil {
				fmt.Fprintf(a.Stderr, "wrap: %v\n", err)
				return ExitError
			}
			n += c
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
	cfgs, code := a.mcpConfigs(*tool, *path, *global, "unwrap")
	if cfgs == nil {
		return code
	}
	n := 0
	for _, cfg := range cfgs {
		c := cfg.Unwrap()
		if c > 0 {
			if err := cfg.Save(); err != nil {
				fmt.Fprintf(a.Stderr, "unwrap: %v\n", err)
				return ExitError
			}
			n += c
		}
	}
	fmt.Fprintf(a.Stdout, "unwrapped %d server(s)\n", n)
	return ExitOK
}

// mcpConfigs validates the tool and returns the MCP config sources to operate
// on. In global mode that is the user-level ~/.claude.json (top-level servers).
// In project mode it is the project's .mcp.json (when present) plus the project's
// per-project entry inside ~/.claude.json — where Claude Code keeps servers added
// at "local" scope. A missing .mcp.json is not an error as long as some source
// exists. On failure it reports and returns nil with the exit code to use.
func (a *App) mcpConfigs(tool, path string, global bool, cmd string) ([]*mcpconfig.Config, int) {
	if tool != "claude-code" {
		fmt.Fprintf(a.Stderr, "%s: tool %q not supported yet (only claude-code)\n", cmd, tool)
		return nil, ExitUsage
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
		return nil, ExitError
	}
	claudeJSON := filepath.Join(home, ".claude.json")

	if global {
		cfg, err := mcpconfig.Load(claudeJSON)
		if err != nil {
			fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
			return nil, ExitError
		}
		return []*mcpconfig.Config{cfg}, ExitOK
	}

	var out []*mcpconfig.Config
	// The project's committable .mcp.json — optional (absent is fine).
	if cfg, err := mcpconfig.Load(filepath.Join(path, ".mcp.json")); err == nil {
		out = append(out, cfg)
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(a.Stderr, "%s: %v\n", cmd, err)
		return nil, ExitError
	}
	// Claude Code's per-project store, keyed by absolute project path — optional.
	if abs, err := filepath.Abs(path); err == nil {
		if cfg, err := mcpconfig.LoadClaudeProject(claudeJSON, abs); err == nil {
			out = append(out, cfg)
		}
	}
	if len(out) == 0 {
		fmt.Fprintf(a.Stderr, "%s: no MCP config found (.mcp.json or ~/.claude.json)\n", cmd)
		return nil, ExitError
	}
	return out, ExitOK
}

func (a *App) printWrapStatus(cfgs []*mcpconfig.Config) int {
	seen := map[string]bool{}
	for _, cfg := range cfgs {
		for _, s := range cfg.Servers() {
			if seen[s.Name] {
				continue // the same server can appear in both sources
			}
			seen[s.Name] = true
			switch {
			case s.Remote:
				fmt.Fprintf(a.Stdout, "  %-20s remote (not wrappable yet)\n", s.Name)
			case s.Wrapped:
				fmt.Fprintf(a.Stdout, "  %-20s wrapped → %s\n", s.Name, strings.Join(append([]string{s.Command}, s.Args...), " "))
			default:
				fmt.Fprintf(a.Stdout, "  %-20s not wrapped (%s)\n", s.Name, s.Command)
			}
		}
	}
	return ExitOK
}
