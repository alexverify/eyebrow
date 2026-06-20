// Package hookconfig installs (and removes) the host-tool hooks that feed
// eyebrow's usage telemetry. A PreToolUse hook on the Skill and Task tools shells
// out to `eyebrow record-use`, so activation of skills and subagents lands in the
// same audit log the MCP shim writes — extending usage telemetry (F1–F4) to
// artifact kinds that have no runtime interposition surface.
//
// It rewrites Claude Code's settings.json the same way mcpconfig rewrites
// .mcp.json: only the hooks eyebrow manages are touched (identified by their
// `record-use` command), every other setting and hook is preserved, and the
// operation is idempotent — re-running install never duplicates an entry.
package hookconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Hook is one command hook.
type Hook struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// Matcher binds a tool-name matcher to a list of hooks.
type Matcher struct {
	Matcher string `json:"matcher,omitempty"`
	Hooks   []Hook `json:"hooks"`
}

// managed is one hook eyebrow owns: a PreToolUse matcher on a tool, recording
// activations of a given artifact kind.
type managed struct {
	event   string
	matcher string
	kind    string
}

// managedEntries are the hooks eyebrow installs. Adding a tool here is the only
// change needed to cover another activation surface.
var managedEntries = []managed{
	{event: "PreToolUse", matcher: "Skill", kind: "skill"},
	{event: "PreToolUse", matcher: "Task", kind: "subagent"},
}

// Config is a loaded settings file.
type Config struct {
	path string
	raw  map[string]any
}

// Load reads a settings file. A missing file is not an error — it yields an
// empty config that Save will create.
func Load(path string) (*Config, error) {
	c := &Config{path: path, raw: map[string]any{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(b, &c.raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.raw == nil {
		c.raw = map[string]any{}
	}
	return c, nil
}

// Save writes the settings back, creating the parent directory if needed.
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c.raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(b, '\n'), 0o644)
}

// hooks decodes the "hooks" subtree into a typed map keyed by event name.
func (c *Config) hooks() (map[string][]Matcher, error) {
	out := map[string][]Matcher{}
	v, ok := c.raw["hooks"]
	if !ok || v == nil {
		return out, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("hooks: %w", err)
	}
	return out, nil
}

// setHooks stores the typed hooks back into raw, dropping the key entirely when
// empty so an uninstall leaves no vestigial "hooks": {}.
func (c *Config) setHooks(h map[string][]Matcher) {
	if len(h) == 0 {
		delete(c.raw, "hooks")
		return
	}
	c.raw["hooks"] = h
}

// commandFor is the record-use invocation for an artifact kind. bin is the
// resolved eyebrow executable (or "eyebrow" to fall back to PATH).
func commandFor(bin, kind string) string {
	return fmt.Sprintf("%s record-use --kind %s --stdin", bin, kind)
}

// isManaged reports whether a hook command is one eyebrow owns.
func isManaged(cmd string) bool { return strings.Contains(cmd, "record-use") }

// Install ensures every managed hook is present with the current command,
// preserving any other hooks on the same matcher. It returns the number of
// matchers newly added (0 on a no-op re-run). Idempotent.
func (c *Config) Install(bin string) (int, error) {
	h, err := c.hooks()
	if err != nil {
		return 0, err
	}
	added := 0
	for _, m := range managedEntries {
		want := commandFor(bin, m.kind)
		matchers := h[m.event]
		idx := -1
		for i := range matchers {
			if matchers[i].Matcher == m.matcher {
				idx = i
				break
			}
		}
		if idx < 0 {
			matchers = append(matchers, Matcher{Matcher: m.matcher, Hooks: []Hook{{Type: "command", Command: want}}})
			added++
			h[m.event] = matchers
			continue
		}
		// Matcher exists: replace a managed hook in place, else append ours,
		// leaving any unrelated hooks on this matcher untouched.
		replaced := false
		for j := range matchers[idx].Hooks {
			if isManaged(matchers[idx].Hooks[j].Command) {
				matchers[idx].Hooks[j].Command = want
				matchers[idx].Hooks[j].Type = "command"
				replaced = true
				break
			}
		}
		if !replaced {
			matchers[idx].Hooks = append(matchers[idx].Hooks, Hook{Type: "command", Command: want})
			added++
		}
		h[m.event] = matchers
	}
	c.setHooks(h)
	return added, nil
}

// Uninstall removes every managed hook, dropping matchers and events left
// empty. It returns the number of hooks removed.
func (c *Config) Uninstall() (int, error) {
	h, err := c.hooks()
	if err != nil {
		return 0, err
	}
	removed := 0
	for event, matchers := range h {
		kept := matchers[:0]
		for _, mt := range matchers {
			hk := mt.Hooks[:0]
			for _, hook := range mt.Hooks {
				if isManaged(hook.Command) {
					removed++
					continue
				}
				hk = append(hk, hook)
			}
			mt.Hooks = hk
			if len(mt.Hooks) > 0 {
				kept = append(kept, mt)
			}
		}
		if len(kept) == 0 {
			delete(h, event)
		} else {
			h[event] = kept
		}
	}
	c.setHooks(h)
	return removed, nil
}

// Status lists the managed hook commands currently installed.
func (c *Config) Status() ([]string, error) {
	h, err := c.hooks()
	if err != nil {
		return nil, err
	}
	var cmds []string
	for _, matchers := range h {
		for _, mt := range matchers {
			for _, hook := range mt.Hooks {
				if isManaged(hook.Command) {
					cmds = append(cmds, hook.Command)
				}
			}
		}
	}
	return cmds, nil
}
