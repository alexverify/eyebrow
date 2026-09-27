package parse

import "testing"

// openclaw.json is JSON5: bare keys, single-quoted strings, comments and
// trailing commas, as in OpenClaw's own config examples.
func TestJSON5ReadsOpenClawConfig(t *testing.T) {
	input := []byte(`{
		// servers
		mcp: {
			servers: {
				docs: { command: 'uvx', args: ['mcp-server-fetch', "--x"], },
				$odd_key1: { url: 'https://example.com/mcp', note: 'it\'s "quoted"', },
			},
		},
		/* skills */
		skills: { load: { extraDirs: ['~/skills'] } },
		'quoted-key': 1,
	}`)
	var got struct {
		MCP struct {
			Servers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
				URL     string   `json:"url"`
				Note    string   `json:"note"`
			} `json:"servers"`
		} `json:"mcp"`
		Skills struct {
			Load struct {
				ExtraDirs []string `json:"extraDirs"`
			} `json:"load"`
		} `json:"skills"`
		Quoted int `json:"quoted-key"`
	}
	if err := JSON5(input, &got); err != nil {
		t.Fatalf("JSON5: %v", err)
	}
	docs := got.MCP.Servers["docs"]
	if docs.Command != "uvx" || len(docs.Args) != 2 || docs.Args[0] != "mcp-server-fetch" || docs.Args[1] != "--x" {
		t.Errorf("docs parsed wrong: %+v", docs)
	}
	odd := got.MCP.Servers["$odd_key1"]
	if odd.URL != "https://example.com/mcp" || odd.Note != `it's "quoted"` {
		t.Errorf("odd parsed wrong: %+v", odd)
	}
	if len(got.Skills.Load.ExtraDirs) != 1 || got.Skills.Load.ExtraDirs[0] != "~/skills" {
		t.Errorf("extraDirs parsed wrong: %+v", got.Skills.Load.ExtraDirs)
	}
	if got.Quoted != 1 {
		t.Errorf("quoted key parsed wrong: %d", got.Quoted)
	}
}

// Words inside strings are values, not keys, and literals stay literals.
func TestJSON5LeavesStringsAndLiteralsAlone(t *testing.T) {
	input := []byte(`{ a: "b: c, d", e: true, f: null, g: -1.5, h: 'x // y' }`)
	var got map[string]any
	if err := JSON5(input, &got); err != nil {
		t.Fatalf("JSON5: %v", err)
	}
	if got["a"] != "b: c, d" || got["e"] != true || got["f"] != nil || got["g"] != -1.5 || got["h"] != "x // y" {
		t.Errorf("parsed wrong: %+v", got)
	}
}

// Plain JSON is valid JSON5.
func TestJSON5AcceptsPlainJSON(t *testing.T) {
	var got map[string]string
	if err := JSON5([]byte(`{"k": "v"}`), &got); err != nil || got["k"] != "v" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
