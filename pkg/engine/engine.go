package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/analyze"
	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/adapters/hash"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/resolve"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// Options configure an Engine. The zero value is valid: native rules only,
// wall clock, default generator string.
type Options struct {
	// SemgrepRulesDir points the optional Semgrep accelerator at a rules pack.
	// Empty, or a directory that does not exist, means native rules only.
	SemgrepRulesDir string
	// Clock stamps GeneratedAt on the lockfile. Nil means time.Now.
	Clock func() time.Time
	// Generator is recorded in the lockfile. Empty means the build user agent.
	Generator string
	// Analyzers run after the native rules on every artifact directory.
	Analyzers []Analyzer
	// Discoverers run beside the built-in discoverers on every project root.
	Discoverers []Discoverer
}

// Engine runs scan and verify on a directory.
type Engine struct {
	scan *scan.Service
}

// New builds an Engine wired with the same adapters the CLI uses.
func New(o Options) *Engine {
	analyzers := []ports.Analyzer{analyze.NewNative(), analyze.NewSemgrep(o.SemgrepRulesDir)}
	for _, a := range o.Analyzers {
		analyzers = append(analyzers, analyzerAdapter{a})
	}
	discoverers := []ports.Discoverer{discover.Default()}
	for _, d := range o.Discoverers {
		discoverers = append(discoverers, discovererAdapter{d})
	}
	deps := scan.Deps{
		Discoverer: discover.NewMulti(discoverers...),
		Resolver:   resolve.NewRouter(),
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyzers...),
		Lock:       lockstore.New(),
		Generator:  o.Generator,
	}
	if o.Clock != nil {
		deps.Clock = ports.ClockFunc(o.Clock)
	}
	return &Engine{scan: scan.New(deps)}
}

// ScanRequest names the directory to scan.
type ScanRequest struct {
	// Root is the project root. Artifact IDs and local source refs derive
	// from it, so use the same value the CLI would be run with (usually ".")
	// when results must match a CLI lockfile.
	Root string
	// Global also scans the user-level tool configuration. Off for hosted use.
	Global bool
	// Policy is an optional policy document in the CLI's JSON format. Nil
	// means the default policy (fail on high or worse).
	Policy []byte
}

// Report is the outcome of a scan.
type Report struct {
	// Lockfile is exactly what `eyebrow scan` would write to eyebrowlock.json.
	Lockfile  json.RawMessage `json:"lockfile"`
	Artifacts []Artifact      `json:"artifacts"`
	Findings  []Finding       `json:"findings"`
	Policy    PolicyResult    `json:"policy"`
	Verdict   string          `json:"verdict"` // "pass" | "fail"
}

// Scan discovers, pins, hashes, and analyzes everything under r.Root and
// applies the policy's finding threshold to the fresh result.
func (e *Engine) Scan(ctx context.Context, r ScanRequest) (Report, error) {
	pol, err := parsePolicy(r.Policy)
	if err != nil {
		return Report{}, err
	}
	lf, err := e.scan.Build(ctx, scopesOf(r.Root, r.Global))
	if err != nil {
		return Report{}, err
	}
	raw, err := lockstore.Marshal(lf)
	if err != nil {
		return Report{}, fmt.Errorf("marshal lockfile: %w", err)
	}
	// An empty locked side makes every finding "new", so the threshold applies
	// to the whole result rather than to a diff against a prior approval.
	pres := policy.Evaluate(pol, lockfile.Lockfile{}, lf)
	return Report{
		Lockfile:  raw,
		Artifacts: artifactsOf(lf),
		Findings:  allFindings(lf),
		Policy:    policyResultOf(pres),
		Verdict:   verdictOf(pres.OK()),
	}, nil
}

func scopesOf(root string, global bool) []ports.Scope {
	var sc []ports.Scope
	if global {
		sc = append(sc, ports.Scope{Kind: "global"})
	}
	return append(sc, ports.Scope{Kind: "project", Path: root})
}

func parsePolicy(raw []byte) (policy.Policy, error) {
	if len(raw) == 0 {
		return policy.Default(), nil
	}
	var p policy.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return policy.Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	return p.Normalize(), nil
}

func verdictOf(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}
