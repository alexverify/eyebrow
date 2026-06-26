package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/hookconfig"
)

// runInstallHooks installs (or reports/removes) the host-tool hooks that feed
// usage telemetry: a PreToolUse hook on Skill and Task routes activations
// through `eyebrow record-use`, so skills and subagents gain the same
// first/last-used, sleeper, and live-finding signals as wrapped MCP servers.
// It rewrites the tool's settings idempotently, mirroring wrap/unwrap.
func (a *App) runInstallHooks(_ context.Context, args []string) int {
	fs := a.flagSet("install-hooks")
	tool := fs.String("tool", "claude-code", "tool whose settings to edit (claude-code only for now)")
	settings := fs.String("settings", "", "settings file to edit (default: ~/.claude/settings.json)")
	status := fs.Bool("status", false, "show install state instead of changing anything")
	uninstall := fs.Bool("uninstall", false, "remove the hooks eyebrow installed")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *tool != "claude-code" {
		fmt.Fprintf(a.Stderr, "install-hooks: tool %q not supported yet (only claude-code)\n", *tool)
		return ExitUsage
	}

	path := *settings
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return a.fail("install-hooks", err)
		}
		path = filepath.Join(home, ".claude", "settings.json")
	}

	cfg, err := hookconfig.Load(path)
	if err != nil {
		return a.fail("install-hooks", err)
	}

	if *status {
		cmds, err := cfg.Status()
		if err != nil {
			return a.fail("install-hooks", err)
		}
		if len(cmds) == 0 {
			fmt.Fprintf(a.Stdout, "no eyebrow hooks installed in %s\n", path)
			return ExitOK
		}
		fmt.Fprintf(a.Stdout, "%d eyebrow hook(s) in %s:\n", len(cmds), path)
		for _, c := range cmds {
			fmt.Fprintf(a.Stdout, "  %s\n", c)
		}
		return ExitOK
	}

	if *uninstall {
		n, err := cfg.Uninstall()
		if err != nil {
			return a.fail("install-hooks", err)
		}
		if n > 0 {
			if err := cfg.Save(); err != nil {
				return a.fail("install-hooks", err)
			}
		}
		fmt.Fprintf(a.Stdout, "removed %d eyebrow hook(s) from %s\n", n, path)
		return ExitOK
	}

	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin = "eyebrow" // fall back to PATH resolution
	}
	added, err := cfg.Install(bin)
	if err != nil {
		return a.fail("install-hooks", err)
	}
	if added > 0 {
		if err := cfg.Save(); err != nil {
			return a.fail("install-hooks", err)
		}
	}
	fmt.Fprintf(a.Stdout, "installed eyebrow usage hooks in %s (%d new); "+
		"skill and subagent activations will be recorded to %s\n", path, added, a.auditDir())
	return ExitOK
}
