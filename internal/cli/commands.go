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
}

func bindCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		path:     fs.String("path", ".", "project root to scan"),
		global:   fs.Bool("global", false, "also include the global (user-home) scope"),
		lockfile: fs.String("lockfile", "eyebrowlock.json", "lockfile path"),
		json:     fs.Bool("json", false, "machine-readable JSON output"),
		rules:    fs.String("rules", "rules", "semgrep rules pack dir (optional accelerator; ignored when absent)"),
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
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	// Read the prior lockfile first (best-effort) so the verdict can report drift
	// against the baseline scan is about to overwrite.
	prior, _ := lockstore.New().Read(ctx, *c.lockfile)

	svc := a.capturingScanService(*c.json, *c.rules, *c.path)
	lf, err := svc.Run(ctx, scan.Options{
		Scopes:       a.scopes(*c.path, *c.global),
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
	if err := fs.Parse(args); err != nil {
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
		Scopes:       a.scopes(*c.path, *c.global),
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
		Scopes:       a.scopes(*c.path, *c.global),
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

	current, err := a.scanService(*c.json, *c.rules).Build(ctx, a.scopes(*c.path, *c.global))
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

	summary := digestSummary(locked, current)
	fmt.Fprint(a.Stdout, summary)
	if *notifyURL != "" {
		if err := notify.New().Post(ctx, *notifyURL, summary); err != nil {
			fmt.Fprintf(a.Stderr, "digest: notify: %v\n", err)
			return ExitError
		}
		fmt.Fprintln(a.Stdout, "\nsent digest to webhook")
	}
	return ExitOK
}

// digestSummary renders the drift-class breakdown and the list of artifacts
// worth reviewing. It uses only the pure domain (Classify + finding counts), so
// it stays in lockstep with the dashboard's interpretation of drift. The string
// is printed to stdout and, optionally, posted to a webhook.
func digestSummary(locked, current lockfile.Lockfile) string {
	classes := lockfile.Classify(locked, current)
	var unchanged, updated, drifted, fresh int
	type change struct{ name, label string }
	var changes []change
	for _, e := range current.Artifacts {
		switch classes[e.ID] {
		case lockfile.DriftClassUpdated:
			updated++
			changes = append(changes, change{e.Name, "updated"})
		case lockfile.DriftClassMutated, lockfile.DriftClassBroken:
			drifted++
			changes = append(changes, change{e.Name, "drifted"})
		case lockfile.DriftClassAdded:
			fresh++
			changes = append(changes, change{e.Name, "new"})
		default:
			unchanged++
		}
	}

	counts := map[finding.Severity]int{}
	total := 0
	for _, e := range current.Artifacts {
		for _, f := range e.Findings {
			counts[f.Severity]++
			total++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "eyebrow digest — %d artifact(s)\n", len(current.Artifacts))
	fmt.Fprintf(&b, "  unchanged: %d\n  updated:   %d\n  drifted:   %d\n  new:       %d\n",
		unchanged, updated, drifted, fresh)
	fmt.Fprintf(&b, "  findings:  %d (critical=%d high=%d medium=%d low=%d)\n",
		total, counts[finding.SeverityCritical], counts[finding.SeverityHigh],
		counts[finding.SeverityMedium], counts[finding.SeverityLow])
	if len(changes) == 0 {
		fmt.Fprint(&b, "\nnothing changed since the lockfile — you're clear.\n")
		return b.String()
	}
	fmt.Fprint(&b, "\nchanges to review:\n")
	for _, ch := range changes {
		fmt.Fprintf(&b, "  [%s] %s\n", ch.label, ch.name)
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
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	lf, err := lockstore.New().Read(ctx, *lock)
	if err != nil {
		return a.fail("sbom", err)
	}
	bom := sbom.Build(lf, a.Clock.Now().UTC().Format(time.RFC3339))
	b, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return a.fail("sbom", err)
	}
	b = append(b, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, b, 0o644); err != nil {
			return a.fail("sbom", err)
		}
		fmt.Fprintf(a.Stdout, "wrote %s (%d component(s))\n", *outPath, len(bom.Components))
		return ExitOK
	}
	_, _ = a.Stdout.Write(b)
	return ExitOK
}

func (a *App) runList(ctx context.Context, args []string) int {
	fs := a.flagSet("list")
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	svc := a.scanService(*c.json, *c.rules)
	lf, err := svc.Build(ctx, a.scopes(*c.path, *c.global))
	if err != nil {
		return a.fail("list", err)
	}
	if err := reporter(*c.json).List(a.Stdout, lf); err != nil {
		return a.fail("list", err)
	}
	return ExitOK
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
