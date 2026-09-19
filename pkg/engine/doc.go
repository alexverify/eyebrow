// Package engine is the public entry point to the eyebrow engine for Go
// programs that embed it: discover every AI tool artifact under a directory,
// pin and hash each one, run the static rules, and compare the result with an
// approved lockfile.
//
// The package wraps the same use cases the eyebrow CLI runs and returns the
// same lockfile bytes, so a lockfile produced here verifies with the CLI and
// the other way round.
//
// Stability: the API is versioned with the module. Until the module reaches
// v1, a breaking change to this package bumps the minor version.
package engine
