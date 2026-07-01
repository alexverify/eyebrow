package cli

import (
	"fmt"
	"strings"

	"github.com/alexverify/eyebrow/internal/buildinfo"
)

// completionCommands are the user-facing subcommands offered by shell
// completion, each with a one-line description for shells that show them (zsh,
// fish). It mirrors the Execute dispatch and the usage() list — kept here as one
// slice so all three shells share a single source of truth.
var completionCommands = []struct{ name, desc string }{
	{"scan", "Discover, resolve, hash, and analyze artifacts; write the lockfile"},
	{"verify", "Recompute and diff against the lockfile"},
	{"diff", "Show what changed since the last lockfile"},
	{"digest", "Summarize what changed since the lockfile"},
	{"sbom", "Export the lockfile as a CycloneDX SBOM"},
	{"list", "Print the current inventory across tools"},
	{"approve", "Mark artifact(s) as approved in the lockfile"},
	{"quarantine", "Disable artifact(s) pending review"},
	{"freeze", "Pin artifact(s); any later drift fails the gate"},
	{"sign", "Sign the lockfile with the local key"},
	{"key", "Manage signing identity and trusted keys"},
	{"wrap", "Route a tool's MCP servers through the auditing shim"},
	{"unwrap", "Restore the original MCP config"},
	{"audit", "Summarize or list the MCP shim's audit log"},
	{"alerts", "List team alerts from the control plane"},
	{"reputation", "Look up or export the reputation corpus"},
	{"record-use", "Record an artifact activation"},
	{"install-hooks", "Install host-tool usage-telemetry hooks"},
	{"dashboard", "Serve a local read-only web dashboard"},
	{"fleet", "Export/push snapshots or verify the fleet"},
	{"serve", "Run the self-hostable team control plane"},
	{"completion", "Print a shell completion script (bash|zsh|fish)"},
	{"version", "Print the version"},
	{"help", "Show help"},
}

// runCompletion prints a shell completion script for the named shell. The script
// is self-contained and generated from completionCommands, so it stays in step
// with the command set without any external template.
func (a *App) runCompletion(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Stderr, "completion: specify a shell (bash|zsh|fish)")
		return ExitUsage
	}
	var script string
	switch args[0] {
	case "bash":
		script = bashCompletion(buildinfo.Name)
	case "zsh":
		script = zshCompletion(buildinfo.Name)
	case "fish":
		script = fishCompletion(buildinfo.Name)
	default:
		fmt.Fprintf(a.Stderr, "completion: unsupported shell %q (want bash|zsh|fish)\n", args[0])
		return ExitUsage
	}
	fmt.Fprint(a.Stdout, script)
	return ExitOK
}

// commandNames returns just the subcommand names, in order.
func commandNames() []string {
	out := make([]string, len(completionCommands))
	for i, c := range completionCommands {
		out[i] = c.name
	}
	return out
}

// bashCompletion completes subcommands at the first position and falls back to
// filenames afterward — enough for `bin -h`-free tab completion without parsing
// every command's flags.
func bashCompletion(bin string) string {
	fn := "_" + strings.ReplaceAll(bin, "-", "_") + "_completion"
	return fmt.Sprintf(`# %[1]s bash completion — source this file or install it in bash-completion.d
%[2]s() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "%[3]s" -- "$cur") )
        return
    fi
    COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -F %[2]s %[1]s
`, bin, fn, strings.Join(commandNames(), " "))
}

// zshCompletion emits a source-able compdef that describes each command with its
// help text. Place it in a directory on $fpath as _%bin, or source it directly.
func zshCompletion(bin string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#compdef %[1]s\n", bin)
	fmt.Fprintf(&b, "_%[1]s() {\n    local -a commands\n    commands=(\n", zshIdent(bin))
	for _, c := range completionCommands {
		fmt.Fprintf(&b, "        '%s:%s'\n", c.name, zshEscape(c.desc))
	}
	fmt.Fprintf(&b, "    )\n    _describe -t commands '%[1]s command' commands\n}\ncompdef _%[2]s %[1]s\n", bin, zshIdent(bin))
	return b.String()
}

// fishCompletion emits one completion rule per command, guarded so the
// subcommand list only appears before a subcommand is chosen (fish completes
// filenames on its own afterward).
func fishCompletion(bin string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %[1]s fish completion — install in ~/.config/fish/completions/%[1]s.fish\n", bin)
	for _, c := range completionCommands {
		fmt.Fprintf(&b, "complete -c %s -n '__fish_use_subcommand' -a '%s' -d '%s'\n", bin, c.name, fishEscape(c.desc))
	}
	return b.String()
}

// zshIdent makes a shell-function-safe identifier from the binary name.
func zshIdent(bin string) string { return strings.ReplaceAll(bin, "-", "_") }

// zshEscape neutralizes the ':' that separates a value from its description in a
// zsh completion spec.
func zshEscape(s string) string { return strings.ReplaceAll(s, ":", " ") }

// fishEscape escapes single quotes for a single-quoted fish string.
func fishEscape(s string) string { return strings.ReplaceAll(s, "'", `\'`) }
