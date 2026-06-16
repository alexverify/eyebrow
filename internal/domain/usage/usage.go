// Package usage turns the runtime audit log into a per-artifact picture of
// what actually ran, and when (theme F). The static scan judges artifacts at
// rest; this package judges their behavior over time. Two pure functions:
//
//   - Summarize folds audit events into a per-server invocation Stat
//     (first used, last used, how many times).
//   - Assess applies the dormant-then-active ("sleeper") rule (F2): an
//     artifact installed long ago, never invoked, that then drifts and fires
//     for the first time — the highest-signal supply-chain event assay can see
//     that a pure static SCA tool cannot.
//
// Like the rest of the domain core it is IO-free: the caller reads the audit
// log and the inventory and passes the facts in.
package usage

import (
	"fmt"
	"time"

	"github.com/alexverify/assay/internal/domain/audit"
)

// Stat is the invocation summary for one artifact (keyed by MCP server name,
// the join key the audit log carries today). Counts cover tool calls only —
// the events that represent the artifact actually doing work.
type Stat struct {
	FirstUsed time.Time `json:"firstUsed"`
	LastUsed  time.Time `json:"lastUsed"`
	Count     int       `json:"count"`
}

// activationPrefix namespaces activation telemetry away from MCP tool-call
// telemetry in the summarized map. MCP servers key on the bare server name (the
// shim's join key); activations key under this prefix. The NUL byte cannot
// appear in a real artifact name, so the two namespaces never collide — a skill
// and an MCP server that happen to share a name never share usage stats.
const activationPrefix = "activation\x00"

// ActivationKey is the map key under which an activated artifact's stats live.
// Callers join non-MCP artifacts (skills, subagents, …) through this key and
// MCP servers through the bare name.
func ActivationKey(name string) string { return activationPrefix + name }

// Summarize folds audit events into per-artifact Stats. Tool calls (MCP
// servers) and activations (skills, subagents, plugins, hooks via the host-tool
// hook) both count as invocations — each is "the artifact ran." They are kept
// in separate namespaces (bare name for MCP, ActivationKey for activations) so
// same-named artifacts of different kinds never conflate. Session lifecycle and
// egress events are not invocations, so they neither inflate the count nor seed
// the first/last timestamps. Artifacts with no invocation are absent from the
// result (a missing key reads as "no usage signal").
func Summarize(events []audit.Event) map[string]Stat {
	out := map[string]Stat{}
	for _, e := range events {
		if e.Server == "" {
			continue
		}
		var key string
		switch e.Kind {
		case audit.KindToolCall:
			key = e.Server
		case audit.KindActivation:
			key = ActivationKey(e.Server)
		default:
			continue
		}
		s := out[key]
		s.Count++
		if s.FirstUsed.IsZero() || e.At.Before(s.FirstUsed) {
			s.FirstUsed = e.At
		}
		if e.At.After(s.LastUsed) {
			s.LastUsed = e.At
		}
		out[key] = s
	}
	return out
}

// DormantThreshold is how long an artifact must lie unused after install before
// its first invocation counts as a sleeper waking. Two weeks separates "set up
// then used in normal course" from "sat untouched, then suddenly fired."
const DormantThreshold = 14 * 24 * time.Hour

// Input is everything the sleeper rule depends on. All of it already exists on
// the dashboard's per-artifact view (install mtime, drift class, first audit
// event), so Assess stays pure.
type Input struct {
	InstalledAt time.Time // when the artifact first appeared (best-effort: file mtime)
	FirstUsed   time.Time // first observed invocation; zero means never invoked
	Drifted     bool      // content changed since the locked snapshot (mutated/broken)
	Now         time.Time // the evaluation clock (the scan time)
}

// Signal is the dormant-then-active assessment.
type Signal struct {
	Sleeper     bool   `json:"sleeper"`
	DormantDays int    `json:"dormantDays"` // days from install to first use
	Detail      string `json:"detail,omitempty"`
}

// Assess fires the sleeper signal when all three legs of the triple hold:
//
//  1. the artifact has drifted (its content is no longer what was locked),
//  2. we know when it was installed, and
//  3. it was first invoked only after lying dormant past DormantThreshold.
//
// Any leg missing makes it not-a-sleeper: no drift is benign churn, no install
// time is inconclusive, and a never-invoked artifact has not yet "fired."
func Assess(in Input) Signal {
	if !in.Drifted || in.InstalledAt.IsZero() || in.FirstUsed.IsZero() {
		return Signal{}
	}
	dormancy := in.FirstUsed.Sub(in.InstalledAt)
	if dormancy < DormantThreshold {
		return Signal{}
	}
	days := int(dormancy / (24 * time.Hour))
	return Signal{
		Sleeper:     true,
		DormantDays: days,
		Detail: fmt.Sprintf(
			"dormant %d days, then its content drifted and it ran for the first time — quarantine and review",
			days,
		),
	}
}
