package cli_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

func TestCompletionRequiresShell(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"completion"}); code != cli.ExitUsage {
		t.Fatalf("completion without a shell exit = %d, want %d", code, cli.ExitUsage)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"completion", "powershell"}); code != cli.ExitUsage {
		t.Fatalf("unknown shell exit = %d, want %d", code, cli.ExitUsage)
	}
}

func TestCompletionScriptsListEveryCommand(t *testing.T) {
	// The subcommands a user expects to tab-complete. Mirrors the Execute
	// dispatch; if a command is added there and here but not offered by
	// completion, this catches it across all three shells.
	want := []string{
		"scan", "verify", "diff", "digest", "sbom", "list", "approve",
		"quarantine", "freeze", "sign", "key", "wrap", "unwrap", "audit",
		"alerts", "reputation", "record-use", "install-hooks", "dashboard",
		"fleet", "serve",
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		app, out, _ := newApp()
		if code := app.Execute(context.Background(), []string{"completion", shell}); code != cli.ExitOK {
			t.Fatalf("%s completion exit = %d", shell, code)
		}
		script := out.String()
		if strings.TrimSpace(script) == "" {
			t.Fatalf("%s completion produced no output", shell)
		}
		for _, c := range want {
			if !strings.Contains(script, c) {
				t.Errorf("%s completion is missing command %q", shell, c)
			}
		}
	}
}

func TestCompletionShellSpecificShape(t *testing.T) {
	// Each shell needs its own dispatch marker to actually register, so a
	// bash script pasted into zsh (or vice versa) is a real regression.
	markers := map[string]string{
		"bash": "complete -F",
		"zsh":  "#compdef",
		"fish": "complete -c",
	}
	for shell, marker := range markers {
		app, out, _ := newApp()
		if code := app.Execute(context.Background(), []string{"completion", shell}); code != cli.ExitOK {
			t.Fatalf("%s completion exit = %d", shell, code)
		}
		if !strings.Contains(out.String(), marker) {
			t.Errorf("%s completion missing expected marker %q", shell, marker)
		}
	}
}
