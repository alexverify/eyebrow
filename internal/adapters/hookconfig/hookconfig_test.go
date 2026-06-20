package hookconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallCreatesHooksThenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	added, err := c.Install("/usr/local/bin/eyebrow")
	if err != nil {
		t.Fatal(err)
	}
	if added != len(managedEntries) {
		t.Fatalf("first install added %d, want %d", added, len(managedEntries))
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	// Re-load and re-install: must be a no-op (idempotent).
	c2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c2.Install("/usr/local/bin/eyebrow")
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Errorf("re-install added %d, want 0 (idempotent)", again)
	}
	st, _ := c2.Status()
	if len(st) != len(managedEntries) {
		t.Errorf("status reports %d managed hooks, want %d", len(st), len(managedEntries))
	}
}

func TestInstallPreservesOtherSettingsAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-guard.sh"}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _ := Load(path)
	if _, err := c.Install("eyebrow"); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(path)
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["model"] != "opus" {
		t.Errorf("unrelated setting lost: model=%v", root["model"])
	}
	// The user's Bash guard must survive alongside our Skill/Task hooks.
	c2, _ := Load(path)
	st, _ := c2.Status()
	if len(st) != len(managedEntries) {
		t.Errorf("managed hooks = %d, want %d", len(st), len(managedEntries))
	}
	hk, _ := c2.hooks()
	var foundGuard bool
	for _, mt := range hk["PreToolUse"] {
		for _, h := range mt.Hooks {
			if h.Command == "my-guard.sh" {
				foundGuard = true
			}
		}
	}
	if !foundGuard {
		t.Errorf("user's pre-existing Bash hook was clobbered")
	}
}

func TestUninstallRemovesOnlyManaged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-guard.sh"}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _ := Load(path)
	c.Install("eyebrow")
	removed, err := c.Uninstall()
	if err != nil {
		t.Fatal(err)
	}
	if removed != len(managedEntries) {
		t.Errorf("removed %d, want %d", removed, len(managedEntries))
	}
	st, _ := c.Status()
	if len(st) != 0 {
		t.Errorf("status after uninstall = %d, want 0", len(st))
	}
	// The user's hook must remain.
	hk, _ := c.hooks()
	if len(hk["PreToolUse"]) != 1 || hk["PreToolUse"][0].Matcher != "Bash" {
		t.Errorf("uninstall disturbed the user's own hook: %+v", hk["PreToolUse"])
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	st, _ := c.Status()
	if len(st) != 0 {
		t.Errorf("empty config should report no hooks")
	}
}
