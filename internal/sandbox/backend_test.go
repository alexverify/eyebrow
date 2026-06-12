package sandbox

import (
	"runtime"
	"strings"
	"testing"
)

func TestNoneBackendIsIdentity(t *testing.T) {
	n := none{}
	argv := []string{"npx", "-y", "some-mcp"}
	out, err := n.Wrap(argv)
	if err != nil {
		t.Fatalf("none.Wrap: %v", err)
	}
	if strings.Join(out, " ") != strings.Join(argv, " ") {
		t.Errorf("none backend must pass argv through unchanged, got %v", out)
	}
	if n.Available() {
		t.Error("none backend must report unavailable")
	}
	if n.Name() != "none" {
		t.Errorf("Name = %q", n.Name())
	}
}

func TestSeatbeltWrapsArgv(t *testing.T) {
	sb := &seatbelt{bin: "/usr/bin/sandbox-exec"}
	out, err := sb.Wrap([]string{"npx", "server"})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// sandbox-exec -p <profile> -- npx server
	if out[0] != "/usr/bin/sandbox-exec" || out[1] != "-p" {
		t.Fatalf("expected sandbox-exec -p ..., got %v", out)
	}
	tail := out[len(out)-3:]
	if strings.Join(tail, " ") != "-- npx server" {
		t.Errorf("argv must follow a -- separator, got %v", out)
	}
	if !strings.Contains(out[2], "(deny default)") {
		t.Errorf("profile arg missing, got %q", out[2])
	}
}

func TestBwrapWrapsArgv(t *testing.T) {
	bw := &bwrap{bin: "/usr/bin/bwrap", profile: sampleProfile()}
	out, err := bw.Wrap([]string{"node", "srv.js"})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if out[0] != "/usr/bin/bwrap" {
		t.Fatalf("expected bwrap first, got %v", out)
	}
	joined := strings.Join(out, " ")
	if !strings.HasSuffix(joined, "-- node srv.js") {
		t.Errorf("argv must follow a -- separator, got %v", out)
	}
}

func TestSelectChoosesByPlatformAndAvailability(t *testing.T) {
	// Force each backend present/absent via the lookPath hook.
	defer func() { lookPath = realLookPath }()

	lookPath = func(string) (string, error) { return "", errNotFound }
	if b := Select(sampleProfile()); b.Name() != "none" {
		t.Errorf("no binaries available must select none, got %q", b.Name())
	}

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	b := Select(sampleProfile())
	switch runtime.GOOS {
	case "darwin":
		if b.Name() != "seatbelt" {
			t.Errorf("darwin with sandbox-exec must select seatbelt, got %q", b.Name())
		}
	case "linux":
		if b.Name() != "bwrap" {
			t.Errorf("linux with bwrap must select bwrap, got %q", b.Name())
		}
	default:
		if b.Name() != "none" {
			t.Errorf("unsupported OS must select none, got %q", b.Name())
		}
	}
}
