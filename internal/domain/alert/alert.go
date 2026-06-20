// Package alert derives team-level alerts from what the control plane actually
// holds: the aggregated fleet report (which artifacts drifted or are quarantined,
// and on how many machines) and the ingested audit events (which wrapped servers
// were blocked from egress or had a tool call denied). It is pure — the caller
// supplies the already-computed report and events.
//
// It deliberately does NOT invent finding-level alerts: fleet snapshots are
// content-free (no findings), so a "new critical finding across the fleet" alert
// would require richer snapshots than eyebrow ships today. We alert on what we can
// prove from the data on hand, and name the gap rather than fake it — the same
// honesty discipline as reachability and the MCP-name usage join.
package alert

import (
	"fmt"
	"sort"

	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
)

// Kind is the alert category.
type Kind string

const (
	KindDrift        Kind = "drift"         // an artifact drifted on one or more machines
	KindQuarantine   Kind = "quarantine"    // a quarantined artifact is still installed somewhere
	KindEgressDenied Kind = "egress_denied" // a wrapped server was blocked reaching a host
	KindToolDenied   Kind = "tool_denied"   // a tool call was blocked by policy
)

// Severity ranks an alert for triage.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityInfo     Severity = "info"
)

func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	default:
		return 1
	}
}

// Alert is one team-level signal worth surfacing.
type Alert struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`         // artifact name or egress host
	Detail   string   `json:"detail"`          // human one-liner
	Count    int      `json:"count,omitempty"` // machines affected, or occurrences
}

// Derive builds the alert list from the fleet report and audit events, most
// urgent first (severity, then count, then subject for stability).
func Derive(rep fleet.Report, events []audit.Event) []Alert {
	var out []Alert

	for _, e := range rep.Exposures {
		if e.Quarantine > 0 {
			out = append(out, Alert{
				Kind:     KindQuarantine,
				Severity: SeverityCritical,
				Subject:  e.Name,
				Count:    e.Quarantine,
				Detail:   fmt.Sprintf("quarantined but still installed on %d of %d machine(s)", e.Quarantine, e.Installs),
			})
		}
		if e.Drifted > 0 {
			out = append(out, Alert{
				Kind:     KindDrift,
				Severity: SeverityHigh,
				Subject:  e.Name,
				Count:    e.Drifted,
				Detail:   fmt.Sprintf("drifted on %d of %d machine(s)", e.Drifted, e.Installs),
			})
		}
	}

	// Audit-derived security events: count denials by host (egress) and by server
	// (tool calls), so a single noisy host or tool yields one alert, not many.
	egress := map[string]int{}
	tools := map[string]int{}
	for _, ev := range events {
		if ev.Status != audit.StatusDenied {
			continue
		}
		switch ev.Kind {
		case audit.KindEgress:
			if ev.Host != "" {
				egress[ev.Host]++
			}
		case audit.KindToolCall:
			if ev.Server != "" {
				tools[ev.Server]++
			}
		}
	}
	for host, n := range egress {
		out = append(out, Alert{
			Kind:     KindEgressDenied,
			Severity: SeverityHigh,
			Subject:  host,
			Count:    n,
			Detail:   fmt.Sprintf("egress to %s blocked %d time(s)", host, n),
		})
	}
	for server, n := range tools {
		out = append(out, Alert{
			Kind:     KindToolDenied,
			Severity: SeverityInfo,
			Subject:  server,
			Count:    n,
			Detail:   fmt.Sprintf("%d tool call(s) denied by policy on %s", n, server),
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := sevRank(out[i].Severity), sevRank(out[j].Severity); ri != rj {
			return ri > rj
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}
