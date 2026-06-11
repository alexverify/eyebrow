package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
)

// TestDiscoverySeesThroughShimmedServers: a wrapped config entry must yield
// the SAME artifact as its unwrapped form, otherwise `agentguard wrap` would
// make every server look rug-pulled on the next verify.
func TestDiscoverySeesThroughShimmedServers(t *testing.T) {
	plain := t.TempDir()
	writeFile(t, filepath.Join(plain, ".mcp.json"), `{
  "mcpServers": {
    "local-tool": {"command": "./server.sh"}
  }
}`)
	writeFile(t, filepath.Join(plain, "server.sh"), "#!/bin/sh\necho hi\n")

	wrapped := t.TempDir()
	writeFile(t, filepath.Join(wrapped, ".mcp.json"), `{
  "mcpServers": {
    "local-tool": {
      "command": "/usr/local/bin/agentguard",
      "args": ["mcp-shim", "--server", "local-tool", "--", "./server.sh"]
    }
  }
}`)
	writeFile(t, filepath.Join(wrapped, "server.sh"), "#!/bin/sh\necho hi\n")

	d := NewClaudeCode()
	get := func(dir string) artifact.Artifact {
		arts, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range arts {
			if a.Type == artifact.TypeMCPServer && a.Name == "local-tool" {
				return a
			}
		}
		t.Fatalf("no mcp server discovered in %s", dir)
		return artifact.Artifact{}
	}

	p, w := get(plain), get(wrapped)
	if w.Source.Kind != p.Source.Kind {
		t.Errorf("source kind differs: plain %q vs wrapped %q", p.Source.Kind, w.Source.Kind)
	}
	// Local-path sources are absolute, so compare the relevant tail.
	if filepath.Base(w.Source.Ref) != filepath.Base(p.Source.Ref) || filepath.Base(w.Source.Ref) != "server.sh" {
		t.Errorf("wrapped source must resolve to the underlying server: plain %q vs wrapped %q", p.Source.Ref, w.Source.Ref)
	}
}
