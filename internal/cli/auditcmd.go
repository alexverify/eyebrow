package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/audit"
)

// runAudit queries the shim's audit log: a summary by default, or a filtered
// event list with --list. Filters compose (server, tool, status, kind, since).
func (a *App) runAudit(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "push" {
		return a.auditPush(ctx, args[1:])
	}
	fs := a.flagSet("audit")
	dir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	server := fs.String("server", "", "only events for this server")
	tool := fs.String("tool", "", "only events for this tool")
	status := fs.String("status", "", "only events with this status (ok|denied|error|unanswered)")
	kind := fs.String("kind", "", "only events of this kind (tool_call|activation|egress|session_start|server_exit)")
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

// auditPush uploads this machine's local audit events to the control plane
// (opt-in). The events are content-free by construction — arguments are stored
// only as digests and secrets are redacted at the shim — so what leaves is tool
// and server names, egress hosts, timings, statuses, and digests, never raw
// values. See docs/privacy.md.
func (a *App) auditPush(ctx context.Context, args []string) int {
	fs := a.flagSet("audit push")
	dir := fs.String("audit-dir", a.auditDir(), "audit log directory")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	since := fs.String("since", "", "only push events on/after this date (YYYY-MM-DD)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *server == "" {
		fmt.Fprintln(a.Stderr, "audit push: set --server (or EYEBROW_SERVER) to a control-plane URL")
		return ExitUsage
	}

	var filter auditlog.Filter
	if *since != "" {
		t, err := time.Parse("2006-01-02", *since)
		if err != nil {
			fmt.Fprintf(a.Stderr, "audit push: bad --since date %q (want YYYY-MM-DD)\n", *since)
			return ExitUsage
		}
		filter.Since = t
	}
	events, err := auditlog.Read(*dir, filter)
	if err != nil {
		fmt.Fprintf(a.Stderr, "audit push: %v\n", err)
		return ExitError
	}
	if len(events) == 0 {
		fmt.Fprintf(a.Stdout, "audit push: no events in %s — nothing to send\n", *dir)
		return ExitOK
	}
	if err := client.New(*server, *token).IngestAudit(ctx, events); err != nil {
		fmt.Fprintf(a.Stderr, "audit push: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "pushed %d audit event(s) → %s\n", len(events), *server)
	return ExitOK
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
		case audit.KindActivation:
			line += fmt.Sprintf(" %s", e.Tool) // the artifact kind
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
	fmt.Fprintf(a.Stdout, "  tool calls:  %d (%d denied)\n", s.ToolCalls, denials(events, audit.KindToolCall))
	if s.Activations > 0 {
		fmt.Fprintf(a.Stdout, "  activations: %d\n", s.Activations)
	}
	fmt.Fprintf(a.Stdout, "  egress:      %d (%d denied, %d redactions)\n", s.Egress, denials(events, audit.KindEgress), s.Redactions)
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
