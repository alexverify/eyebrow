package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/domain/audit"
)

// runRecordUse appends a single activation event to the audit log: the
// host-tool hook surface that lets usage telemetry (F1–F4) cover skills,
// subagents, plugins, and hooks, not just wrapped MCP servers. It is invoked
// by a tool hook on every activation, so its overriding contract is to NEVER
// fail the host tool: a missing name, an unparseable hook payload, or a write
// error all degrade to exit 0 and simply record nothing — the same discipline
// the MCP shim follows. It records only that an artifact ran and when; it never
// carries arguments (those routinely hold secrets).
func (a *App) runRecordUse(_ context.Context, args []string) int {
	fs := a.flagSet("record-use")
	dir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	kind := fs.String("kind", "", "artifact kind (skill|subagent|plugin|hook|rule)")
	name := fs.String("name", "", "artifact name (the usage join key)")
	session := fs.String("session", "", "optional session id tying related activations together")
	fromStdin := fs.Bool("stdin", false, "read a host-tool hook JSON payload on stdin and extract the name from tool_input")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	artifact := strings.TrimSpace(*name)
	if *fromStdin {
		if n := nameFromHookPayload(a.Stdin); n != "" {
			artifact = n
		}
	}
	if artifact == "" {
		// Nothing to record. Degrade silently — never break the host tool.
		return ExitOK
	}

	e := audit.Event{
		At:      a.Clock.Now().UTC(),
		Session: strings.TrimSpace(*session),
		Server:  artifact,
		Kind:    audit.KindActivation,
		Tool:    strings.TrimSpace(*kind),
		Status:  audit.StatusOK,
	}
	if err := auditlog.New(*dir).Emit(context.Background(), e); err != nil {
		// A logging failure must not propagate to the host tool.
		fmt.Fprintf(a.Stderr, "record-use: %v\n", err)
	}
	return ExitOK
}

// nameFromHookPayload pulls an artifact name out of a host-tool hook JSON
// payload (Claude Code PreToolUse shape: {"tool_name":…,"tool_input":{…}}).
// The field naming the artifact differs by tool — a skill names it in
// command/skill/name, a subagent in subagent_type — so we try each in turn and
// take the first non-empty string. Any parse failure yields "" (the caller
// then records nothing); a hook must never crash the host.
func nameFromHookPayload(r io.Reader) string {
	if r == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return ""
	}
	var p struct {
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	for _, k := range []string{"command", "skill", "name", "subagent_type"} {
		if v, ok := p.ToolInput[k].(string); ok {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return ""
}
