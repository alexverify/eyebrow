package parse

import "testing"

func TestTOMLParsesTablesAndArrays(t *testing.T) {
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `toml:"command"`
			Args    []string `toml:"args"`
		} `toml:"mcp_servers"`
	}
	input := []byte(`
[mcp_servers.x]
command = "npx"
args = ["-y", "pkg@1.0.0"]
`)
	if err := TOML(input, &cfg); err != nil {
		t.Fatalf("TOML: %v", err)
	}
	x := cfg.MCPServers["x"]
	if x.Command != "npx" || len(x.Args) != 2 || x.Args[1] != "pkg@1.0.0" {
		t.Fatalf("parsed wrong: %+v", x)
	}
}
