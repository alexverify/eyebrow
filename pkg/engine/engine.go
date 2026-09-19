package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/analyze"
	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/adapters/hash"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/resolve"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/app/verify"
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
	// Offline restricts resolution to local and inline sources: no git, npm,
	// or network fetch ever runs. A remote source (npm, git, url, container,
	// registry) degrades to the same unresolved-source finding it would get
	// for any other unsupported kind, rather than being attempted. Use this
	// when the engine runs somewhere without network access, or where a
	// hosted caller wants to sandbox network activity by simply not needing
	// it.
	Offline bool
}

// Engine runs scan and verify on a directory.
type Engine struct {
	scan   *scan.Service
	verify *verify.Service
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
	resolver := resolve.NewRouter()
	if o.Offline {
		resolver = resolve.NewOfflineRouter()
	}
	deps := scan.Deps{
		Discoverer: discover.NewMulti(discoverers...),
		Resolver:   resolver,
		Hasher:     hash.New(),
		Analyzer:   analyze.NewChain(analyzers...),
		Lock:       lockstore.New(),
		Generator:  o.Generator,
	}
	if o.Clock != nil {
		deps.Clock = ports.ClockFunc(o.Clock)
	}
	sc := scan.New(deps)
	return &Engine{
		scan:   sc,
		verify: verify.New(verify.Deps{Builder: sc}),
	}
}

// ScanRequest names the directory to scan.
type ScanRequest struct {
	// Root is the project root. Artifact IDs and local source refs derive
	// from it, so use the same value the CLI would be run with (usually ".")
	// when results must match a CLI lockfile. Because IDs and refs derive from
	// this exact string, a caller that needs results comparable across
	// machines or directories — for example scanning in one directory and
	// verifying the lockfile against another checkout of the same project —
	// must set the working directory to the project root and pass Root: "."
	// on every call, exactly as the CLI does. A different Root string (an
	// absolute path, or a path relative to a different cwd) for the "same"
	// project yields different artifact IDs and reads as drift even though
	// nothing changed. There is no option to normalise this away: the
	// relative-root convention is the one stable identity scheme, so use it
	// rather than a machine-specific absolute path.
	Root string
	// Global also scans the user-level tool configuration. Off for hosted use.
	Global bool
	// Policy is an optional policy document in the CLI's JSON format. Nil
	// means the default policy (fail on high or worse). Approval and freeze
	// rules (RequireApproval, RequireSignedApproval) do not apply to a fresh
	// scan, since there is no prior approval to check against; only findings,
	// capability expansion, and publisher/artifact block lists are evaluated.
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
	if err := checkRoot(r.Root); err != nil {
		return Report{}, err
	}
	pol, err := parsePolicy(r.Policy)
	if err != nil {
		return Report{}, err
	}
	// A fresh scan has no prior approvals to check against, so approval and
	// freeze rules never apply here — only findings, capabilities, and block
	// lists do. See ScanRequest.Policy.
	pol.RequireApproval = false
	pol.RequireSignedApproval = false
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

// VerifyRequest compares the tree under Root with an approved lockfile.
type VerifyRequest struct {
	// Root is the project root, with the same stability requirement as
	// ScanRequest.Root: artifact IDs and local source refs derive from this
	// exact string, so comparing against a lockfile produced elsewhere (a
	// different machine or checkout of the same project) requires running
	// with the working directory set to the project and Root: ".", exactly
	// as the CLI does.
	Root   string
	Global bool
	// Expected is the lockfile JSON to compare against, as produced by Scan
	// or by `eyebrow scan`.
	Expected []byte
	// Policy is applied as `verify --ci` applies it. Nil means the default.
	Policy []byte
}

// VerifyReport is the outcome of a verify.
type VerifyReport struct {
	Status  string       `json:"status"` // "clean" | "drift"
	Changes []Change     `json:"changes"`
	Policy  PolicyResult `json:"policy"`
	Verdict string       `json:"verdict"` // "pass" | "fail"
}

// Verify rebuilds the current state under r.Root and compares it with
// r.Expected. Verdict follows the same rules as `eyebrow verify --ci`.
func (e *Engine) Verify(ctx context.Context, r VerifyRequest) (VerifyReport, error) {
	if err := checkRoot(r.Root); err != nil {
		return VerifyReport{}, err
	}
	var locked lockfile.Lockfile
	if err := json.Unmarshal(r.Expected, &locked); err != nil {
		return VerifyReport{}, fmt.Errorf("parse expected lockfile: %w", err)
	}
	pol, err := parsePolicy(r.Policy)
	if err != nil {
		return VerifyReport{}, err
	}
	res, err := e.verify.Check(ctx, locked, verify.Options{
		Scopes: scopesOf(r.Root, r.Global),
		CI:     true,
		Policy: pol,
	})
	if err != nil {
		return VerifyReport{}, err
	}
	status := "clean"
	if res.Diff.HasDrift() {
		status = "drift"
	}
	return VerifyReport{
		Status:  status,
		Changes: changesOf(res.Diff),
		Policy:  policyResultOf(res.Policy),
		Verdict: verdictOf(res.OK),
	}, nil
}

// checkRoot fails fast on a root that does not exist or is not a directory,
// rather than surfacing whatever error a downstream discoverer happens to
// produce for the same condition.
func checkRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("root %q: %w", root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("root %q is not a directory", root)
	}
	return nil
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
