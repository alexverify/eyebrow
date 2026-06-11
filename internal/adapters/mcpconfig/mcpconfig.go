// Package mcpconfig rewrites MCP server configs (Claude Code's .mcp.json) so
// stdio servers launch through the agentguard shim, and restores them.
//
// The wrapped form is self-describing — the original argv lives after a "--"
// in the shim's arguments — so unwrap and status need no side-channel state:
//
//	{"command": "npx", "args": ["-y", "pkg"]}
//	→ {"command": "<agentguard>", "args": ["mcp-shim", "--server", "<name>", "--", "npx", "-y", "pkg"]}
//
// Everything else in the file (env, unknown fields, remote/SSE entries) is
// preserved untouched. Entries that cannot be restored faithfully are never
// modified.
package mcpconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

const shimSubcommand = "mcp-shim"

// Server is one entry's inspection view.
type Server struct {
	Name    string
	Wrapped bool
	Command string   // the underlying command, even when wrapped
	Args    []string // the underlying args, even when wrapped
	Remote  bool     // url/SSE entries: not wrappable by the stdio shim
}

// Config is a loaded MCP config file.
type Config struct {
	path string
	raw  map[string]any
}

// Load reads an MCP config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Config{path: path, raw: raw}, nil
}

// Save writes the config back, indented for human diffing.
func (c *Config) Save() error {
	b, err := json.MarshalIndent(c.raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(b, '\n'), 0o644)
}

// servers returns the mcpServers map, or nil when absent.
func (c *Config) servers() map[string]any {
	m, _ := c.raw["mcpServers"].(map[string]any)
	return m
}

// inspect classifies one entry without modifying it.
func inspect(name string, entry map[string]any) Server {
	s := Server{Name: name}
	if _, hasURL := entry["url"]; hasURL {
		s.Remote = true
		return s
	}
	cmd, _ := entry["command"].(string)
	args := stringSlice(entry["args"])
	if orig, ok := unwrapArgv(args); ok {
		s.Wrapped = true
		s.Command = orig[0]
		s.Args = orig[1:]
		return s
	}
	s.Command = cmd
	s.Args = args
	return s
}

// Servers lists all entries, sorted by name.
func (c *Config) Servers() []Server {
	var out []Server
	for name, v := range c.servers() {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, inspect(name, entry))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Wrap rewrites every unwrapped stdio entry to launch through the shim at
// bin. It returns how many entries changed.
func (c *Config) Wrap(bin string) int {
	changed := 0
	for name, v := range c.servers() {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		s := inspect(name, entry)
		if s.Remote || s.Wrapped || s.Command == "" {
			continue
		}
		shimArgs := append([]string{shimSubcommand, "--server", name, "--", s.Command}, s.Args...)
		entry["command"] = bin
		entry["args"] = toAnySlice(shimArgs)
		changed++
	}
	return changed
}

// Unwrap restores every wrapped entry to its original command and args. It
// returns how many entries changed.
func (c *Config) Unwrap() int {
	changed := 0
	for name, v := range c.servers() {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		s := inspect(name, entry)
		if !s.Wrapped {
			continue
		}
		entry["command"] = s.Command
		if len(s.Args) > 0 {
			entry["args"] = toAnySlice(s.Args)
		} else {
			delete(entry, "args")
		}
		changed++
	}
	return changed
}

// unwrapArgv recognizes the shim's argument shape and returns the original
// argv after "--". A malformed shim entry (no "--", nothing after it) is not
// considered wrapped — it will never be modified.
func unwrapArgv(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != shimSubcommand {
		return nil, false
	}
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			return args[i+1:], true
		}
	}
	return nil, false
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
