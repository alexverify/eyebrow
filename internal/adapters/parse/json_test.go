package parse

import "testing"

func TestJSONParsesStrictObjects(t *testing.T) {
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	input := []byte(`{"mcpServers":{"x":{"command":"npx","args":["-y","pkg@1.0.0"]}}}`)
	if err := JSON(input, &cfg); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	x, ok := cfg.MCPServers["x"]
	if !ok || x.Command != "npx" || len(x.Args) != 2 {
		t.Fatalf("parsed = %+v", cfg)
	}
}

// Unlike JSONC, JSON is strict: comments and trailing commas are a hard error.
func TestJSONRejectsComments(t *testing.T) {
	if err := JSON([]byte(`{"a":1,}`), &struct{ A int }{}); err == nil {
		t.Error("strict JSON must reject a trailing comma")
	}
}
