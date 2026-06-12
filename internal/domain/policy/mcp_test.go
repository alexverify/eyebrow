package policy

import "testing"

func TestDecideToolDefaultAllow(t *testing.T) {
	p := Policy{} // no mcp rules at all
	if d := p.DecideTool("github", "create_issue"); !d.Allowed {
		t.Fatalf("no rules must allow everything, got %+v", d)
	}
}

func TestDecideToolDenyWins(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"github": {AllowTools: []string{"delete_repo"}, DenyTools: []string{"delete_repo"}},
	}}}
	d := p.DecideTool("github", "delete_repo")
	if d.Allowed {
		t.Fatal("deny must win over allow")
	}
	if d.Reason == "" {
		t.Error("a denial must carry the matched rule as reason")
	}
}

func TestDecideToolAllowlistRestricts(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"github": {AllowTools: []string{"get_*", "list_issues"}},
	}}}
	for tool, want := range map[string]bool{
		"get_issue":   true,
		"list_issues": true,
		"create_repo": false,
	} {
		if d := p.DecideTool("github", tool); d.Allowed != want {
			t.Errorf("DecideTool(github, %s) = %v, want %v (%s)", tool, d.Allowed, want, d.Reason)
		}
	}
	// Other servers are untouched by github's allowlist.
	if d := p.DecideTool("filesystem", "write_file"); !d.Allowed {
		t.Errorf("other servers must not inherit github's allowlist: %+v", d)
	}
}

func TestDecideToolGlobDeny(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"db": {DenyTools: []string{"drop_*", "execute_raw"}},
	}}}
	if d := p.DecideTool("db", "drop_table"); d.Allowed {
		t.Fatal("glob deny must match drop_table")
	}
	if d := p.DecideTool("db", "select"); !d.Allowed {
		t.Fatal("unmatched tools stay allowed")
	}
}

func TestDecideToolStarServerAppliesEverywhere(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"*":  {DenyTools: []string{"execute_*"}},
		"db": {AllowTools: []string{"select", "execute_safe"}},
	}}}
	// Star denies apply on top of server-specific allows.
	if d := p.DecideTool("db", "execute_safe"); d.Allowed {
		t.Fatal("star-server deny must apply to every server")
	}
	if d := p.DecideTool("db", "select"); !d.Allowed {
		t.Fatal("select is allowlisted and not star-denied")
	}
	if d := p.DecideTool("anything", "execute_cmd"); d.Allowed {
		t.Fatal("star deny must reach servers with no specific entry")
	}
	if d := p.DecideTool("anything", "harmless"); !d.Allowed {
		t.Fatal("tools outside the star deny stay allowed")
	}
}

func TestDecideHostSemanticsMirrorTools(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"github": {AllowHosts: []string{"api.github.com", "*.githubusercontent.com"}},
		"*":      {DenyHosts: []string{"*.evil.example"}},
	}}}

	for _, tc := range []struct {
		server, host string
		want         bool
	}{
		{"github", "api.github.com", true},
		{"github", "raw.githubusercontent.com", true},
		{"github", "exfil.attacker.net", false}, // allowlist is exhaustive
		{"github", "cdn.evil.example", false},   // star deny stacks on top
		{"other", "anywhere.example", true},     // no rules for this server
		{"other", "x.evil.example", false},      // star deny reaches everyone
	} {
		if d := p.DecideHost(tc.server, tc.host); d.Allowed != tc.want {
			t.Errorf("DecideHost(%s, %s) = %v, want %v (%s)", tc.server, tc.host, d.Allowed, tc.want, d.Reason)
		}
	}
}

func TestDecideHostNoRulesAllows(t *testing.T) {
	if d := (Policy{}).DecideHost("any", "example.com"); !d.Allowed {
		t.Fatalf("no network rules must allow everything: %+v", d)
	}
}

func TestDecideToolServerAllowlistFallsBackToStar(t *testing.T) {
	p := Policy{MCP: MCPPolicy{Servers: map[string]ToolRule{
		"*": {AllowTools: []string{"read_*"}},
	}}}
	if d := p.DecideTool("fs", "read_file"); !d.Allowed {
		t.Fatal("star allowlist must apply to all servers")
	}
	if d := p.DecideTool("fs", "write_file"); d.Allowed {
		t.Fatal("star allowlist must restrict all servers")
	}
}
