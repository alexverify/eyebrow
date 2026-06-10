// Package parse normalizes the heterogeneous config formats used by AI coding
// tools into Go values: JSON, JSONC (Claude/Cursor/VS Code-style, with comments
// and trailing commas), and TOML (Codex). Discovery picks the reader that
// matches each tool's config format.
package parse

import (
	"encoding/json"

	"github.com/BurntSushi/toml"
)

// JSON unmarshals strict JSON into v.
func JSON(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

// TOML unmarshals TOML (e.g. Codex's config.toml) into v.
func TOML(b []byte, v any) error {
	return toml.Unmarshal(b, v)
}
