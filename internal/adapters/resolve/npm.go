package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/agentguard/internal/app/ports"
	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/platform/run"
)

// npmFetcher downloads and extracts a package's code for hashing.
type npmFetcher interface {
	fetch(ctx context.Context, spec string) (dir string, err error)
}

// NPM resolves npm/npx sources: it pins the exact version and npm integrity,
// and fetches the package code into a temp directory for hashing/analysis.
type NPM struct {
	Runner  run.Runner
	Fetcher npmFetcher
}

// NewNPM builds an NPM resolver with the real pack-based fetcher.
func NewNPM(r run.Runner) NPM {
	return NPM{Runner: r, Fetcher: packFetcher{runner: r}}
}

// Resolve satisfies ports.Resolver.
func (n NPM) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	name, version, pinned := parseNPMSpec(src.Ref)
	if name == "" {
		return ports.Resolution{Warnings: []finding.Finding{{
			RuleID: "NPM-NO-PACKAGE", Severity: finding.SeverityMedium, OWASP: "ASK-02",
			Explanation: "npm source has no resolvable package spec",
		}}}, nil
	}

	var warnings []finding.Finding
	if !pinned {
		warnings = append(warnings, finding.Finding{
			RuleID: "UNPINNED-NPM", Severity: finding.SeverityHigh, OWASP: "ASK-02",
			Explanation: fmt.Sprintf("npm package %q is unpinned (%q); a moving target cannot be locked", name, src.Ref),
		})
	}

	spec := name
	if version != "" {
		spec = name + "@" + version
	}
	out, err := n.Runner.Run(ctx, "npm", "view", spec, "version", "--json")
	if err != nil {
		return ports.Resolution{}, fmt.Errorf("npm view %s version: %w", spec, err)
	}
	concrete := parseNPMStringOutput(out)
	if concrete == "" {
		return ports.Resolution{}, fmt.Errorf("npm: could not resolve a concrete version for %q", spec)
	}
	pinnedSpec := name + "@" + concrete

	integrity := ""
	if iout, ierr := n.Runner.Run(ctx, "npm", "view", pinnedSpec, "dist.integrity", "--json"); ierr == nil {
		integrity = parseNPMStringOutput(iout)
	}

	res := ports.Resolution{PinnedRef: pinnedSpec, Integrity: integrity, Warnings: warnings}

	dir, ferr := n.Fetcher.fetch(ctx, pinnedSpec)
	if ferr != nil {
		res.Warnings = append(res.Warnings, finding.Finding{
			RuleID: "NPM-FETCH-FAILED", Severity: finding.SeverityMedium, OWASP: "ASK-02",
			Explanation: "could not fetch package code for hashing: " + ferr.Error(),
		})
	} else {
		res.LocalPath = dir
	}
	return res, nil
}

// packFetcher downloads a package via `npm pack` and extracts it for hashing.
type packFetcher struct {
	runner run.Runner
}

// fetch creates a temp directory and delegates to fetchInto.
func (p packFetcher) fetch(ctx context.Context, spec string) (string, error) {
	tmp, err := os.MkdirTemp("", "agentguard-npm-*")
	if err != nil {
		return "", err
	}
	return p.fetchInto(ctx, spec, tmp)
}

// fetchInto runs `npm pack` into destDir, then extracts the resulting tarball
// into destDir/package-root and returns that path. Split out from fetch so the
// destination is injectable in tests.
func (p packFetcher) fetchInto(ctx context.Context, spec, destDir string) (string, error) {
	out, err := p.runner.Run(ctx, "npm", "pack", spec, "--pack-destination", destDir, "--json")
	if err != nil {
		return "", fmt.Errorf("npm pack %s: %w", spec, err)
	}
	filename, err := parseNPMPackFilename(out)
	if err != nil {
		return "", err
	}
	tarPath := filepath.Join(destDir, filepath.Base(filename))
	root := filepath.Join(destDir, "package-root")
	if err := extractTarGz(tarPath, root); err != nil {
		return "", fmt.Errorf("extract %s: %w", tarPath, err)
	}
	return root, nil
}

// parseNPMPackFilename reads the tarball filename from `npm pack --json` output,
// which is a JSON array of objects each with a "filename" field.
func parseNPMPackFilename(b []byte) (string, error) {
	var entries []struct {
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(b, &entries); err == nil && len(entries) > 0 && entries[0].Filename != "" {
		return entries[0].Filename, nil
	}
	// Fallback: older npm prints the bare filename.
	if s := strings.TrimSpace(string(b)); s != "" && !strings.HasPrefix(s, "[") {
		return s, nil
	}
	return "", fmt.Errorf("npm pack: could not parse tarball filename from %q", b)
}
