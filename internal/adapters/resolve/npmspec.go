package resolve

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// npmNameRE matches a registry package name: an optional scope, then a name,
// each lowercase alphanumerics plus ".", "_", "-". npm names are at most 214
// characters (enforced separately, since a plain regex quantifier bound reads
// worse than a length check).
var npmNameRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// npmVersionRE matches a registry version or range: digits, letters, and the
// semver-range punctuation npm accepts (^, ~, comparisons, ||, *, x, +, -, .).
// It excludes ":", "/", and whitespace, which is how git specs, tarball URLs,
// and multi-clause ranges with spaces are rejected.
var npmVersionRE = regexp.MustCompile(`^[0-9A-Za-z.^~><=|*x+-]*$`)

// npmStrictVersionRE matches a single concrete semver version: no range
// operators, tags, wildcards, scheme prefixes, or paths — exactly what a
// well-behaved registry's `npm view <spec> version` returns.
var npmStrictVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)

// isStrictVersion reports whether v is a single concrete semver version
// (major.minor.patch, with an optional pre-release/build suffix) and nothing
// else. A registry response is trusted to feed further npm invocations only
// after passing this check: a malicious or compromised registry (for example
// one a scanned repo's .npmrc points at) could otherwise answer a `version`
// query with a git or tarball URL spec, which npm's own spec dispatch would
// then clone or download regardless of --ignore-scripts.
func isStrictVersion(v string) bool {
	return npmStrictVersionRE.MatchString(v)
}

// isRegistrySpec reports whether ref names a package on a registry: an
// optional scope, a name, and an optional version or range. Git specs,
// tarball URLs, file paths, and aliases are rejected so npm never clones,
// downloads from an arbitrary host, or reads a local path.
func isRegistrySpec(ref string) bool {
	if ref == "" {
		return false
	}
	name, version, _ := parseNPMSpec(ref)
	if name == "" || len(name) > 214 || !npmNameRE.MatchString(name) {
		return false
	}
	if version != "" && !npmVersionRE.MatchString(version) {
		return false
	}
	return true
}

// parseNPMSpec splits an npm spec into name, version, and whether the version
// is an exact pin. Handles scoped packages (e.g. @scope/name@1.2.3).
func parseNPMSpec(ref string) (name, version string, pinned bool) {
	if ref == "" {
		return "", "", false
	}
	at := strings.LastIndex(ref, "@")
	if at <= 0 { // no version, or only the leading @ of a scope
		return ref, "", false
	}
	name = ref[:at]
	version = ref[at+1:]
	return name, version, isExactVersion(version)
}

// isExactVersion reports whether v is a single concrete version (no range
// operators, tags, or wildcards).
func isExactVersion(v string) bool {
	if v == "" || v == "latest" || v == "*" || v == "next" {
		return false
	}
	if strings.ContainsAny(v, "^~ ><=|*x") {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

// parseNPMStringOutput extracts a string from `npm view ... --json` output,
// which may be a JSON string or (when multiple versions match) a JSON array;
// in the latter case the last element is returned.
func parseNPMStringOutput(b []byte) string {
	b = bytes.TrimSpace(b)
	var s string
	if json.Unmarshal(b, &s) == nil {
		return s
	}
	var arr []string
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		return arr[len(arr)-1]
	}
	return strings.Trim(string(b), `"`)
}
