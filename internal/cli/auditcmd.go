package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/alexverify/agentguard/internal/adapters/auditlog"
	"github.com/alexverify/agentguard/internal/domain/audit"
)

// runAudit queries the shim's audit log: a summary by default, or a filtered
// event list with --list. Filters compose (server, tool, status, kind, since).
func (a *App) runAudit(_ context.Context, args []string) int {
	fs := a.flagSet("audit")
	dir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	server := fs.String("server", "", "only events for this server")
	tool := fs.String("tool", "", "only events for this tool")
	status := fs.String("status", "", "only events with this status (ok|denied|error|unanswered)")
	kind := fs.String("kind", "", "only events of this kind (tool_call|egress|session_start|server_exit)")
	since := fs.String("since", "", "only events on/after this date (YYYY-MM-DD)")
	list := fs.Bool("list", false, "list matching events instead of a summary")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	filter := auditlog.Filter{
		Server: *server, Tool: *tool, Status: *status, Kind: audit.Kind(*kind),
	}
	if *since != "" {
		t, err := time.Parse("2006-01-02", *since)
		if err != nil {
			fmt.Fprintf(a.Stderr, "audit: bad --since date %q (want YYYY-MM-DD)\n", *since)
			return ExitUsage
		}
		filter.Since = t
	}

	events, err := auditlog.Read(*dir, filter)
	if err != nil {
		fmt.Fprintf(a.Stderr, "audit: %v\n", err)
		return ExitError
	}

	if *list {
		return a.auditList(events, *jsonOut)
	}
	return a.auditSummary(events, *jsonOut, *dir)
}

func (a *App) auditList(events []audit.Event, jsonOut bool) int {
	if jsonOut {
		return a.emitJSON(events)
	}
	if len(events) == 0 {
		fmt.Fprintln(a.Stdout, "no audit events match")
		return ExitOK
	}
	for _, e := range events {
		line := fmt.Sprintf("%s  %-12s %-12s", e.At.UTC().Format("2006-01-02 15:04:05"), e.Server, e.Kind)
		switch e.Kind {
		case audit.KindToolCall:
			line += fmt.Sprintf(" %-16s %s", e.Tool, e.Status)
		case audit.KindEgress:
			line += fmt.Sprintf(" %s %s %s", e.Method, e.Host, e.Status)
			if e.Redactions > 0 {
				line += fmt.Sprintf(" (redacted %d)", e.Redactions)
			}
		default:
			line += " " + e.Detail
		}
		if e.Status == audit.StatusDenied && e.Detail != "" {
			line += "  — " + e.Detail
		}
		fmt.Fprintln(a.Stdout, line)
	}
	return ExitOK
}

func (a *App) auditSummary(events []audit.Event, jsonOut bool, dir string) int {
	s := auditlog.Summarize(events)
	if jsonOut {
		return a.emitJSON(s)
	}
	if s.Total == 0 {
		fmt.Fprintf(a.Stdout, "no audit events in %s\n", dir)
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "%d events across %d session(s)\n", s.Total, s.Sessions)
	fmt.Fprintf(a.Stdout, "  tool calls: %d (%d denied)\n", s.ToolCalls, denials(events, audit.KindToolCall))
	fmt.Fprintf(a.Stdout, "  egress:     %d (%d denied, %d redactions)\n", s.Egress, denials(events, audit.KindEgress), s.Redactions)
	fmt.Fprintln(a.Stdout, "by server:")
	for _, kv := range sortedCounts(s.ByServer) {
		fmt.Fprintf(a.Stdout, "  %-16s %d\n", kv.k, kv.v)
	}
	if len(s.ByTool) > 0 {
		fmt.Fprintln(a.Stdout, "top tools:")
		for _, kv := range topN(sortedCounts(s.ByTool), 10) {
			fmt.Fprintf(a.Stdout, "  %-16s %d\n", kv.k, kv.v)
		}
	}
	return ExitOK
}

func (a *App) emitJSON(v any) int {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(a.Stderr, "audit: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func denials(events []audit.Event, kind audit.Kind) int {
	n := 0
	for _, e := range events {
		if e.Kind == kind && e.Status == audit.StatusDenied {
			n++
		}
	}
	return n
}

type kv struct {
	k string
	v int
}

func sortedCounts(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].k < out[j].k
	})
	return out
}

func topN(items []kv, n int) []kv {
	if len(items) > n {
		return items[:n]
	}
	return items
}
