// Package parse normalizes the heterogeneous config formats used by AI coding
// tools into Go values. JSON is fully supported. JSONC (Claude/VS Code-style,
// with comments and trailing commas) and TOML (Codex) are documented seams:
// they return ErrUnsupportedFormat until a vetted, dependency-free tolerant
// parser is wired, so discovery can note and skip rather than mis-parse.
package parse

import (
	"encoding/json"
	"errors"
)

// ErrUnsupportedFormat indicates a config format whose parser is not yet wired.
var ErrUnsupportedFormat = errors.New("config format not yet supported")

// JSON unmarshals strict JSON into v.
func JSON(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

// JSONC parses JSON-with-comments / trailing commas. Not yet implemented: a
// correct tolerant parser (string-aware comment stripping) is deferred rather
// than shipped subtly wrong in a security tool.
func JSONC(_ []byte, _ any) error {
	return ErrUnsupportedFormat
}

// TOML parses TOML (e.g. Codex config.toml). Not yet implemented; see package
// docs. Adding it is an isolated change behind this seam.
func TOML(_ []byte, _ any) error {
	return ErrUnsupportedFormat
}
