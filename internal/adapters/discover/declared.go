package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// ManifestFile is the committed layout manifest a repo places at its root to
// declare where its skills live. Ten of the first fourteen partner audits
// needed a bespoke Go adapter for exactly this; the manifest lets a repo
// integrate in one PR to itself instead of waiting on an eyebrow release.
const ManifestFile = "eyebrow.discover.json"

// manifest is the parsed eyebrow.discover.json.
type manifest struct {
	// Version is the schema version. Only 1 exists.
	Version int `json:"version"`
	// Name becomes Artifact.Tool for every skill the manifest declares, and so
	// is part of each artifact's ID. A repo migrating off a built-in catalog
	// adapter keeps its lockfile IDs by reusing that adapter's tool id.
	Name string `json:"name"`
	// Skills are globs relative to the repo root. A match is a skill when it
	// is a directory holding SKILL.md. "." declares the whole repo as one skill.
	Skills []string `json:"skills"`
	// Harvest are globs relative to each skill directory. Every URL host in a
	// matched file joins the skill's network capability.
	Harvest []string `json:"harvest"`
}

var manifestName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// loadManifest reads and validates <root>/eyebrow.discover.json. present is
// false only when the file does not exist. Any other failure, including a
// file that exists but is invalid, returns an error naming the file and the
// offending field, so a broken committed manifest fails the scan instead of
// reading as "zero artifacts".
func loadManifest(root string) (m manifest, present bool, err error) {
	f, err := os.Open(filepath.Join(root, ManifestFile))
	if errors.Is(err, os.ErrNotExist) {
		return manifest{}, false, nil
	}
	if err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if err := m.validate(); err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	return m, true, nil
}

func (m manifest) validate() error {
	if m.Version != 1 {
		return fmt.Errorf(`"version" must be 1, got %d`, m.Version)
	}
	if m.Name == "" {
		return errors.New(`"name" is required`)
	}
	if !manifestName.MatchString(m.Name) {
		return fmt.Errorf(`"name" %q must match %s`, m.Name, manifestName)
	}
	if len(m.Skills) == 0 {
		return errors.New(`"skills" must not be empty`)
	}
	if err := validGlobs("skills", m.Skills); err != nil {
		return err
	}
	return validGlobs("harvest", m.Harvest)
}

// validGlobs rejects an entry that escapes the repo root and a pattern with
// bad syntax, so discovery never has to handle a glob error mid-walk.
//
// fs.ValidPath rejects "", a leading "/", a trailing "/", and any "." or
// ".." path element (accepting the lone "." for the repo root itself), so a
// manifest can never point discovery or harvest outside the project root it
// was committed to. This also replaces filepath.IsAbs, which reports false
// for "/abs" on Windows (no volume) and would have let that entry through.
//
// path.Match(g, "") is a syntax-only check: the empty name can never match
// a non-empty pattern, so this only exercises pattern parsing to surface
// path.ErrBadPattern.
func validGlobs(field string, globs []string) error {
	for _, g := range globs {
		if !fs.ValidPath(g) {
			return fmt.Errorf(`"%s" entry %q must be a relative glob`, field, g)
		}
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf(`"%s" entry %q: %w`, field, g, err)
		}
	}
	return nil
}

// Declared discovers skills from a repo's committed eyebrow.discover.json.
// It is inert for any project root without the manifest, reports nothing
// for global and registry scopes, and fails the scan when the manifest is
// present but invalid.
type Declared struct{}

// NewDeclared constructs the declared-layout discoverer.
func NewDeclared() *Declared { return &Declared{} }

// Tool returns the adapter id. Artifacts carry the manifest's name as their
// tool, not this value, so a lockfile shows the catalog's own name.
func (d *Declared) Tool() string { return "declared" }

// Discover satisfies ports.Discoverer.
func (d *Declared) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		m, present, err := loadManifest(sc.Path)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		dirByName := map[string]string{}
		for _, dir := range m.skillDirs(sc.Path) {
			skillMd := filepath.Join(dir, "SKILL.md")
			name := skillName(dir, sc.Path, skillMd)
			if prev, ok := dirByName[name]; ok {
				return nil, fmt.Errorf(`%s: "skills" matches two directories named %q: %s, %s`, ManifestFile, name, prev, dir)
			}
			dirByName[name] = dir
			a := artifact.Artifact{
				Tool:           m.Name,
				Scope:          sc.String(),
				Type:           artifact.TypeSkill,
				Name:           name,
				Source:         artifact.Source{Kind: artifact.SourceLocal, Ref: dir},
				DiscoveredFrom: skillMd,
				Description:    frontmatterDescription(skillMd),
				Capabilities:   m.capabilities(dir, skillMd),
			}
			a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
			out = append(out, a)
		}
	}
	return out, nil
}

// skillDirs expands the manifest's skill globs against root and returns the
// directories that hold a SKILL.md, in manifest order then lexical order,
// each reported once. Symlinked directories are followed. Patterns were
// validated at load, so a glob error here cannot happen.
//
// Matching goes through fs.Glob(os.DirFS(root), g) rather than
// filepath.Glob(filepath.Join(root, g)): fs.Glob only ever matches g against
// the tree inside root, so it can neither escape root (a validated pattern
// cannot contain ".." anyway, but this keeps the walk itself confined) nor
// have root's own path treated as part of the glob pattern, which is what
// let filepath.Glob silently discover nothing for a root path containing a
// metacharacter such as "[wip]".
func (m manifest) skillDirs(root string) []string {
	seen := map[string]bool{}
	var dirs []string
	fsys := os.DirFS(root)
	for _, g := range m.Skills {
		matches, _ := fs.Glob(fsys, g)
		sort.Strings(matches)
		for _, match := range matches {
			dir := filepath.Join(root, filepath.FromSlash(match))
			if seen[dir] {
				continue
			}
			info, err := os.Stat(dir) // follows a symlinked skill dir
			if err != nil || !info.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// skillName is the directory base name for a catalog entry. For the repo
// root itself ("." in the manifest) it is the frontmatter name, falling back
// to the checkout's directory name.
func skillName(dir, root, skillMd string) string {
	if filepath.Clean(dir) != filepath.Clean(root) {
		return filepath.Base(dir)
	}
	if n := frontmatterValue(skillMd, "name"); n != "" {
		return n
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	return filepath.Base(abs)
}

// networkCapabilities turns a host set into the sorted Network capability,
// or the zero value when the set is empty.
func networkCapabilities(hosts map[string]bool) artifact.Capabilities {
	if len(hosts) == 0 {
		return artifact.Capabilities{}
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return artifact.Capabilities{Network: out}
}

// capabilities merges the SKILL.md call-line fingerprint with every host in
// the manifest's harvest files. SKILL.md keeps the call-line rule so a doc
// link in prose stays out; harvest files are an explicit opt-in by the
// author, so every host in them counts.
func (m manifest) capabilities(dir, skillMd string) artifact.Capabilities {
	hosts := map[string]bool{}
	for _, h := range capabilitiesFromSkill(skillMd).Network {
		hosts[h] = true
	}
	fsys := os.DirFS(dir)
	for _, g := range m.Harvest {
		matches, _ := fs.Glob(fsys, g) // validated at load, confined to dir
		for _, match := range matches {
			f := filepath.Join(dir, filepath.FromSlash(match))
			for _, h := range hostsInFile(f) {
				hosts[h] = true
			}
		}
	}
	return networkCapabilities(hosts)
}

// hostsInFile returns every URL host found on any line of a regular file.
// Unreadable paths and directories yield nothing.
func hostsInFile(path string) []string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var hosts []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, raw := range urlHost.FindAllString(sc.Text(), -1) {
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				hosts = append(hosts, u.Host)
			}
		}
	}
	return hosts
}
