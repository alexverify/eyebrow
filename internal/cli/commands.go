package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/historystore"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/notify"
	"github.com/alexverify/eyebrow/internal/adapters/sbom"
	"github.com/alexverify/eyebrow/internal/adapters/sign"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/app/scan"
	"github.com/alexverify/eyebrow/internal/app/verify"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/posture"
)

// commonFlags are shared by the read pipeline commands.
type commonFlags struct {
	path     *string
	global   *bool
	lockfile *string
	json     *bool
	rules    *string
	registry *string
}

func bindCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		path:     fs.String("path", ".", "project root to scan"),
		global:   fs.Bool("global", false, "also include the global (user-home) scope"),
		lockfile: fs.String("lockfile", "eyebrowlock.json", "lockfile path"),
		json:     fs.Bool("json", false, "machine-readable JSON output"),
		rules:    fs.String("rules", "rules", "semgrep rules pack dir (optional accelerator; ignored when absent)"),
		// Opt-in: unlike the local scopes, reading a catalog makes network
		// calls. verify accepts it too — a registry scanned but not verified
		// would read as wholesale removal on the next run.
		registry: fs.String("registry", "", "also scan a remote app registry by base URL (e.g. https://www.agentos.services)"),
	}
}

func (a *App) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

func (a *App) runScan(ctx context.Context, args []string) int {
	fs := a.flagSet("scan")
	c := bindCommon(fs)
	tool := fs.String("tool", "", "only discover artifacts from this tool (e.g. openclaw)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !a.selectTool("scan", *tool) {
		return ExitUsage
	}
	// Read the prior lockfile first (best-effort) so the verdict can report drift
	// against the baseline scan is about to overwrite.
	prior, _ := lockstore.New().Read(ctx, *c.lockfile)

	svc := a.capturingScanService(*c.json, *c.rules, *c.path)
	lf, err := svc.Run(ctx, scan.Options{
		Scopes:       a.scopes(*c.path, *c.global, *c.registry),
		LockfilePath: *c.lockfile,
	}, a.Stdout)
	if err != nil {
		return a.fail("scan", err)
	}

	// The single-verdict summary (E2): the first-run "are we OK?" line, and a
	// counts-only data point appended to the local posture trend. Suppressed in
	// JSON mode to keep machine output clean.
	if !*c.json {
		p := posture.Summarize(lf, prior, posture.ApprovedSet(prior), a.Clock.Now().UTC())
		fmt.Fprintln(a.Stdout, p.Line())
		if err := historystore.Append(a.historyPath(), p); err != nil {
			fmt.Fprintf(a.Stderr, "scan: history: %v\n", err)
		}
	}
	return ExitOK
}

func (a *App) runVerify(ctx context.Context, args []string) int {
	fs := a.flagSet("verify")
	c := bindCommon(fs)
	ci := fs.Bool("ci", false, "strict mode: also apply the policy gate (severity threshold, approvals)")
	policyPath := fs.String("policy", "eyebrow.policy.json", "policy file applied in --ci mode")
	trustedKeys := fs.String("trusted-keys", "eyebrow.trustedkeys", "committed trusted-keys registry checked by requireSignature")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL (opt-in: pull org policy and trusted keys)")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	tool := fs.String("tool", "", "only discover artifacts from this tool (e.g. openclaw)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !a.selectTool("verify", *tool) {
		return ExitUsage
	}

	pol, err := a.resolvePolicy(ctx, *server, *token, *policyPath)
	if err != nil {
		return a.fail("verify", err)
	}
	verifier, err := a.lockfileVerifierWithServer(ctx, *trustedKeys, *server, *token)
	if err != nil {
		return a.fail("verify", err)
	}

	svc := a.verifyService(*c.json, *c.rules, verifier)
	res, err := svc.Run(ctx, verify.Options{
		Scopes:       a.scopes(*c.path, *c.global, *c.registry),
		LockfilePath: *c.lockfile,
		CI:           *ci,
		Policy:       pol,
	}, a.Stdout)
	if err != nil {
		return a.fail("verify", err)
	}
	for _, v := range res.Policy.Violations {
		switch v.Kind {
		case "unapproved":
			fmt.Fprintf(a.Stdout, "policy: unapproved artifact %s (%s)\n", v.Name, v.ID)
		case "unsigned_approval":
			fmt.Fprintf(a.Stdout, "policy: approval not validly signed — %s %s\n", v.Name, v.Detail)
		case "quarantined":
			fmt.Fprintf(a.Stdout, "policy: quarantined artifact still installed — %s (%s)\n", v.Name, v.ID)
		case "frozen_drift":
			fmt.Fprintf(a.Stdout, "policy: frozen artifact changed (%s) — %s (%s)\n", v.Detail, v.Name, v.ID)
		case "capability_expanded":
			_, _ = fmt.Fprintf(a.Stdout, "policy: capability expansion — %s gained %s (%s)\n", v.Name, v.Detail, v.ID)
		case "blocked_publisher":
			fmt.Fprintf(a.Stdout, "policy: blocked publisher %q — %s (%s)\n", v.Detail, v.Name, v.ID)
		case "blocked_artifact":
			fmt.Fprintf(a.Stdout, "policy: blocked artifact %q — %s (%s)\n", v.Detail, v.Name, v.ID)
		case "not_allowlisted":
			fmt.Fprintf(a.Stdout, "policy: publisher not in the allowlist — %s (%s)\n", v.Name, v.ID)
		case "signature":
			fmt.Fprintf(a.Stdout, "policy: signature — %s\n", v.Detail)
		default:
			fmt.Fprintf(a.Stdout, "policy: %s %s %s\n", v.Severity, v.RuleID, v.Detail)
		}
	}
	if !res.OK {
		return ExitDrift
	}
	return ExitOK
}

// runDiff is verify without the failing exit code: informational only.
func (a *App) runDiff(ctx context.Context, args []string) int {
	fs := a.flagSet("diff")
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	svc := a.verifyService(*c.json, *c.rules, nil)
	_, err := svc.Run(ctx, verify.Options{
		Scopes:       a.scopes(*c.path, *c.global, *c.registry),
		LockfilePath: *c.lockfile,
	}, a.Stdout)
	if err != nil {
		return a.fail("diff", err)
	}
	return ExitOK
}

// runDigest summarizes what changed since the lockfile — the "what should I
// review?" view, suitable for a terminal glance or a cron/CI step. It never
// fails on drift (informational, exit 0); it is the read-side companion to the
// dashboard's Changes view.
func (a *App) runDigest(ctx context.Context, args []string) int {
	fs := a.flagSet("digest")
	c := bindCommon(fs)
	notifyURL := fs.String("notify", "", "POST the digest to this webhook (Slack-compatible {\"text\":…})")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	current, err := a.scanService(*c.json, *c.rules).Build(ctx, a.scopes(*c.path, *c.global, *c.registry))
	if err != nil {
		return a.fail("digest", err)
	}
	locked, err := lockstore.New().Read(ctx, *c.lockfile)
	if err != nil && !errors.Is(err, ports.ErrNoLockfile) {
		return a.fail("digest", err)
	}

	// Append a counts-only posture snapshot so the dashboard trend gains a data
	// point from each digest run (best-effort; a history error never fails the digest).
	p := posture.Summarize(current, locked, posture.ApprovedSet(locked), a.Clock.Now().UTC())
	if err := historystore.Append(a.historyPath(), p); err != nil {
		fmt.Fprintf(a.Stderr, "digest: history: %v\n", err)
	}

	report := buildDigest(locked, current)
	summary := renderDigest(report)
	if *c.json {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return a.fail("digest", err)
		}
		fmt.Fprintf(a.Stdout, "%s\n", b)
	} else {
		fmt.Fprint(a.Stdout, summary)
	}
	// The webhook always receives the human-readable summary (Slack-compatible),
	// independent of the stdout format.
	if *notifyURL != "" {
		if err := notify.New().Post(ctx, *notifyURL, summary); err != nil {
			fmt.Fprintf(a.Stderr, "digest: notify: %v\n", err)
			return ExitError
		}
		if !*c.json {
			fmt.Fprintln(a.Stdout, "\nsent digest to webhook")
		}
	}
	return ExitOK
}

// digestSummary renders the drift-class breakdown and the list of artifacts
// worth reviewing. It uses only the pure domain (Classify + finding counts), so
// it stays in lockstep with the dashboard's interpretation of drift. The string
// is printed to stdout and, optionally, posted to a webhook.
func digestSummary(locked, current lockfile.Lockfile) string {
	return renderDigest(buildDigest(locked, current))
}

// digestChange is one artifact worth reviewing, with why (updated|drifted|new).
type digestChange struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// digestFindings is the severity breakdown of static-analysis findings.
type digestFindings struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// digestReport is the structured "what should I review?" summary, shared by the
// text renderer and the --json output so both stay in lockstep.
type digestReport struct {
	Artifacts int            `json:"artifacts"`
	Unchanged int            `json:"unchanged"`
	Updated   int            `json:"updated"`
	Drifted   int            `json:"drifted"`
	New       int            `json:"new"`
	Findings  digestFindings `json:"findings"`
	Changes   []digestChange `json:"changes"`
}

// buildDigest classifies the current inventory against the locked baseline. It
// uses only the pure domain (Classify + finding counts), so it stays in lockstep
// with the dashboard's interpretation of drift.
func buildDigest(locked, current lockfile.Lockfile) digestReport {
	classes := lockfile.Classify(locked, current)
	r := digestReport{Artifacts: len(current.Artifacts), Changes: []digestChange{}}
	for _, e := range current.Artifacts {
		switch classes[e.ID] {
		case lockfile.DriftClassUpdated:
			r.Updated++
			r.Changes = append(r.Changes, digestChange{e.Name, "updated"})
		case lockfile.DriftClassMutated, lockfile.DriftClassBroken:
			r.Drifted++
			r.Changes = append(r.Changes, digestChange{e.Name, "drifted"})
		case lockfile.DriftClassAdded:
			r.New++
			r.Changes = append(r.Changes, digestChange{e.Name, "new"})
		default:
			r.Unchanged++
		}
	}
	for _, e := range current.Artifacts {
		for _, f := range e.Findings {
			r.Findings.Total++
			switch f.Severity {
			case finding.SeverityCritical:
				r.Findings.Critical++
			case finding.SeverityHigh:
				r.Findings.High++
			case finding.SeverityMedium:
				r.Findings.Medium++
			case finding.SeverityLow:
				r.Findings.Low++
			}
		}
	}
	return r
}

// renderDigest formats a digest report as the human-readable summary.
func renderDigest(r digestReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "eyebrow digest — %d artifact(s)\n", r.Artifacts)
	fmt.Fprintf(&b, "  unchanged: %d\n  updated:   %d\n  drifted:   %d\n  new:       %d\n",
		r.Unchanged, r.Updated, r.Drifted, r.New)
	fmt.Fprintf(&b, "  findings:  %d (critical=%d high=%d medium=%d low=%d)\n",
		r.Findings.Total, r.Findings.Critical, r.Findings.High, r.Findings.Medium, r.Findings.Low)
	if len(r.Changes) == 0 {
		fmt.Fprint(&b, "\nnothing changed since the lockfile — you're clear.\n")
		return b.String()
	}
	fmt.Fprint(&b, "\nchanges to review:\n")
	for _, ch := range r.Changes {
		fmt.Fprintf(&b, "  [%s] %s\n", ch.Label, ch.Name)
	}
	return b.String()
}

// runSBOM exports the committed lockfile as a CycloneDX 1.6 SBOM — components
// for every artifact plus findings rendered as vulnerabilities — to stdout or a
// file. It is the auditable supply-chain document a customer might ask for.
func (a *App) runSBOM(ctx context.Context, args []string) int {
	fs := a.flagSet("sbom")
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile to export")
	outPath := fs.String("o", "", "write to this file instead of stdout")
	format := fs.String("format", "cyclonedx", "SBOM format: cyclonedx | spdx")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	lf, err := lockstore.New().Read(ctx, *lock)
	if err != nil {
		return a.fail("sbom", err)
	}
	ts := a.Clock.Now().UTC().Format(time.RFC3339)
	var doc any
	var count int
	switch *format {
	case "cyclonedx":
		bom := sbom.Build(lf, ts)
		doc, count = bom, len(bom.Components)
	case "spdx":
		d := sbom.BuildSPDX(lf, ts)
		doc, count = d, len(d.Packages)
	default:
		fmt.Fprintf(a.Stderr, "sbom: unknown format %q (want cyclonedx or spdx)\n", *format)
		return ExitUsage
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return a.fail("sbom", err)
	}
	b = append(b, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, b, 0o644); err != nil {
			return a.fail("sbom", err)
		}
		fmt.Fprintf(a.Stdout, "wrote %s (%d component(s))\n", *outPath, count)
		return ExitOK
	}
	_, _ = a.Stdout.Write(b)
	return ExitOK
}

func (a *App) runList(ctx context.Context, args []string) int {
	fs := a.flagSet("list")
	c := bindCommon(fs)
	tool := fs.String("tool", "", "only artifacts from this tool (e.g. cursor)")
	typ := fs.String("type", "", "only artifacts of this type ("+strings.Join(typeNames(), "|")+")")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *typ != "" && !artifact.IsType(*typ) {
		fmt.Fprintf(a.Stderr, "list: unknown --type %q (want %s)\n", *typ, strings.Join(typeNames(), ", "))
		return ExitUsage
	}
	svc := a.scanService(*c.json, *c.rules)
	lf, err := svc.Build(ctx, a.scopes(*c.path, *c.global, *c.registry))
	if err != nil {
		return a.fail("list", err)
	}
	lf.Artifacts = filterEntries(lf.Artifacts, *tool, *typ)
	if err := reporter(*c.json).List(a.Stdout, lf); err != nil {
		return a.fail("list", err)
	}
	return ExitOK
}

// filterEntries narrows a lockfile's entries to those matching a tool and/or
// type. An empty selector matches everything; tool matching is case-insensitive.
func filterEntries(entries []lockfile.Entry, tool, typ string) []lockfile.Entry {
	if tool == "" && typ == "" {
		return entries
	}
	out := make([]lockfile.Entry, 0, len(entries))
	for _, e := range entries {
		if tool != "" && !strings.EqualFold(e.Tool, tool) {
			continue
		}
		if typ != "" && string(e.Type) != typ {
			continue
		}
		out = append(out, e)
	}
	return out
}

// typeNames lists the valid --type values for help and error text.
func typeNames() []string {
	types := artifact.Types()
	out := make([]string, len(types))
	for i, ty := range types {
		out[i] = string(ty)
	}
	return out
}

func (a *App) runApprove(ctx context.Context, args []string) int {
	fs := a.flagSet("approve")
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile path")
	all := fs.Bool("all", false, "approve every artifact in the lockfile (bulk onboarding)")
	signApproval := fs.Bool("sign", false, "cryptographically sign each approval with your local key")
	key := fs.String("key", a.keyPath(), "ed25519 private key path for --sign (created if absent)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	ids := fs.Args()
	if *all && len(ids) > 0 {
		fmt.Fprintln(a.Stderr, "approve: --all and explicit IDs are mutually exclusive")
		return ExitUsage
	}
	if !*all && len(ids) == 0 {
		fmt.Fprintln(a.Stderr, "approve: provide one or more artifact IDs (prefixes accepted), or --all")
		return ExitUsage
	}

	store := lockstore.New()
	lf, err := store.Read(ctx, *lock)
	if err != nil {
		return a.fail("approve", err)
	}

	var signer *sign.Signer
	if *signApproval {
		signer, err = sign.LoadOrCreate(*key)
		if err != nil {
			return a.fail("approve", err)
		}
	}

	now := a.Clock.Now().UTC()
	who := currentUser()
	matched := 0
	for i := range lf.Artifacts {
		if *all || matchesAnyPrefix(lf.Artifacts[i].ID, ids) {
			lf.Artifacts[i].Approval = &lockfile.Approval{Status: "approved", By: who, At: now}
			if signer != nil {
				sig, serr := signer.SignApproval(lf.Artifacts[i])
				if serr != nil {
					return a.fail("approve", serr)
				}
				lf.Artifacts[i].Approval.Sig = sig
			}
			matched++
		}
	}
	if matched == 0 {
		fmt.Fprintf(a.Stderr, "approve: no artifact matched %v\n", ids)
		return ExitError
	}
	if err := store.Write(ctx, *lock, lf); err != nil {
		return a.fail("approve", err)
	}
	fmt.Fprintf(a.Stdout, "approved %d artifact(s)\n", matched)
	return ExitOK
}

// runQuarantine disables artifact(s) pending review: the policy gate fails any
// quarantined artifact that is still installed.
func (a *App) runQuarantine(ctx context.Context, args []string) int {
	return a.runMark(ctx, "quarantine", args, func(e *lockfile.Entry, on bool) { e.Quarantined = on })
}

// runFreeze pins artifact(s): any later drift on a frozen artifact is a hard
// policy violation rather than a reviewable change.
func (a *App) runFreeze(ctx context.Context, args []string) int {
	return a.runMark(ctx, "freeze", args, func(e *lockfile.Entry, on bool) { e.Frozen = on })
}

// runMark is the shared read-modify-write for the lockfile remediation flags
// (quarantine, freeze). set toggles the relevant flag; --remove lifts it.
func (a *App) runMark(ctx context.Context, name string, args []string, set func(*lockfile.Entry, bool)) int {
	fs := a.flagSet(name)
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile path")
	all := fs.Bool("all", false, "apply to every artifact in the lockfile")
	remove := fs.Bool("remove", false, "lift the "+name+" instead of applying it")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	ids := fs.Args()
	if *all && len(ids) > 0 {
		fmt.Fprintf(a.Stderr, "%s: --all and explicit IDs are mutually exclusive\n", name)
		return ExitUsage
	}
	if !*all && len(ids) == 0 {
		fmt.Fprintf(a.Stderr, "%s: provide one or more artifact IDs (prefixes accepted), or --all\n", name)
		return ExitUsage
	}

	store := lockstore.New()
	lf, err := store.Read(ctx, *lock)
	if err != nil {
		return a.fail(name, err)
	}

	matched := 0
	for i := range lf.Artifacts {
		if *all || matchesAnyPrefix(lf.Artifacts[i].ID, ids) {
			set(&lf.Artifacts[i], !*remove)
			matched++
		}
	}
	if matched == 0 {
		fmt.Fprintf(a.Stderr, "%s: no artifact matched %v\n", name, ids)
		return ExitError
	}
	if err := store.Write(ctx, *lock, lf); err != nil {
		return a.fail(name, err)
	}
	action := name
	if *remove {
		action = "un" + name
	}
	fmt.Fprintf(a.Stdout, "%s: updated %d artifact(s)\n", action, matched)
	return ExitOK
}

func (a *App) runSign(ctx context.Context, args []string) int {
	fs := a.flagSet("sign")
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile to sign")
	key := fs.String("key", a.keyPath(), "ed25519 private key path (created if absent)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	signer, err := sign.LoadOrCreate(*key)
	if err != nil {
		return a.fail("sign", err)
	}
	store := lockstore.New()
	lf, err := store.Read(ctx, *lock)
	if err != nil {
		return a.fail("sign", err)
	}
	signed, err := signer.SignLockfile(lf)
	if err != nil {
		return a.fail("sign", err)
	}
	if err := store.Write(ctx, *lock, signed); err != nil {
		return a.fail("sign", err)
	}
	fmt.Fprintf(a.Stdout, "signed %s with key %s\n", *lock, signer.PublicKeyBase64())
	return ExitOK
}

// runKey dispatches the key subcommands: `key show` prints (creating if
// needed) the local public key to share with a team; `key trust` adds a
// teammate's public key to a trusted-keys registry.
func (a *App) runKey(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Stderr, "key: usage: eyebrow key <show|trust> [flags]")
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "show":
		return a.runKeyShow(rest)
	case "trust":
		return a.runKeyTrust(rest)
	default:
		fmt.Fprintf(a.Stderr, "key: unknown subcommand %q (want show or trust)\n", sub)
		return ExitUsage
	}
}

func (a *App) runKeyShow(args []string) int {
	fs := a.flagSet("key show")
	key := fs.String("key", a.keyPath(), "ed25519 private key path (created if absent)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	signer, err := sign.LoadOrCreate(*key)
	if err != nil {
		return a.fail("key show", err)
	}
	fmt.Fprintln(a.Stdout, signer.PublicKeyBase64())
	return ExitOK
}

func (a *App) runKeyTrust(args []string) int {
	fs := a.flagSet("key trust")
	file := fs.String("file", a.trustedKeysPath(), "trusted-keys registry to add the key to")
	name := fs.String("name", "", "optional label for the key (e.g. who owns it)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.Stderr, "key trust: provide exactly one base64 public key (from 'eyebrow key show')")
		return ExitUsage
	}
	if err := sign.AppendTrustedKey(*file, fs.Arg(0), *name); err != nil {
		return a.fail("key trust", err)
	}
	fmt.Fprintf(a.Stdout, "trusted key added to %s\n", *file)
	return ExitOK
}

func matchesAnyPrefix(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
