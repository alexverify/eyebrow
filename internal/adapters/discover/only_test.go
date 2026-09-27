package discover

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
)

// Only keeps one tool's discoverers, so a scan of the user's home does not
// pull in every other tool's configs.
func TestOnlyKeepsOneTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("OPENCLAW_STATE_DIR", "")
	project := t.TempDir()
	writeFile(t, filepath.Join(project, ".mcp.json"), `{"mcpServers":{"cc":{"command":"npx","args":["-y","cc@1.0.0"]}}}`)
	writeFile(t, filepath.Join(home, ".openclaw", "skills", "demo", "SKILL.md"), "---\ndescription: demo\n---\n")

	only, err := Only("OpenClaw") // case-insensitive, like list --tool
	if err != nil {
		t.Fatalf("Only: %v", err)
	}
	arts, err := only.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: project}, {Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(arts) != 1 || arts[0].Tool != "openclaw" || arts[0].Name != "demo" {
		t.Fatalf("want only the openclaw skill, got %+v", arts)
	}
}

func TestOnlyRejectsUnknownTool(t *testing.T) {
	_, err := Only("nope")
	if err == nil {
		t.Fatal("want an error for an unknown tool")
	}
	if !strings.Contains(err.Error(), `unknown tool "nope"`) || !strings.Contains(err.Error(), "openclaw") {
		t.Errorf("error must name the tool and list valid ids: %v", err)
	}
}
