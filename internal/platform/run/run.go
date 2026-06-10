// Package run abstracts external command execution so adapters that shell out
// (npm, git) can be unit-tested with a scripted fake instead of a real process.
package run

import (
	"context"
	"os/exec"
)

// Runner executes an external command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OS is the production Runner backed by os/exec.
type OS struct{}

// Run executes the command, returning stdout. On a non-zero exit the error is
// an *exec.ExitError whose Stderr is populated.
func (OS) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
