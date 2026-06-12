package sandbox

import (
	"errors"
	"os/exec"
	"runtime"
)

// Backend wraps a server's argv in an OS confinement. The zero confinement
// (none) returns argv unchanged, so an unavailable sandbox degrades to the
// shim's prior observe-only behavior rather than failing the session.
type Backend interface {
	// Wrap returns the argv to exec instead of the original.
	Wrap(argv []string) ([]string, error)
	// Available reports whether this backend's binary is present.
	Available() bool
	// Name identifies the backend for audit/status output.
	Name() string
}

// lookPath is indirected for tests.
var (
	lookPath     = realLookPath
	errNotFound  = errors.New("not found")
	realLookPath = exec.LookPath
)

// Select returns the best available backend for the host and profile:
// Seatbelt on macOS, bubblewrap on Linux, else the identity backend.
func Select(p Profile) Backend {
	switch runtime.GOOS {
	case "darwin":
		if bin, err := lookPath("sandbox-exec"); err == nil {
			return &seatbelt{bin: bin, profile: p}
		}
	case "linux":
		if bin, err := lookPath("bwrap"); err == nil {
			return &bwrap{bin: bin, profile: p}
		}
	}
	return none{}
}

// none applies no confinement.
type none struct{}

func (none) Wrap(argv []string) ([]string, error) { return argv, nil }
func (none) Available() bool                      { return false }
func (none) Name() string                         { return "none" }

// seatbelt confines via macOS sandbox-exec.
type seatbelt struct {
	bin     string
	profile Profile
}

func (s *seatbelt) Wrap(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("sandbox: empty argv")
	}
	out := []string{s.bin, "-p", seatbeltProfile(s.profile), "--"}
	return append(out, argv...), nil
}
func (s *seatbelt) Available() bool { return s.bin != "" }
func (s *seatbelt) Name() string    { return "seatbelt" }

// bwrap confines via Linux bubblewrap.
type bwrap struct {
	bin     string
	profile Profile
}

func (b *bwrap) Wrap(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("sandbox: empty argv")
	}
	out := append([]string{b.bin}, bwrapArgs(b.profile)...)
	out = append(out, "--")
	return append(out, argv...), nil
}
func (b *bwrap) Available() bool { return b.bin != "" }
func (b *bwrap) Name() string    { return "bwrap" }
