package cli_test

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

var update = flag.Bool("update", false, "rewrite golden files under testdata")

var contentHashRe = regexp.MustCompile(`"contentHash": "[^"]*"`)

// The check JSON is a contract the OpenClaw plugin parses; this pins its
// whole shape byte-for-byte. Only the content hash is masked.
func TestCheckJSONGolden(t *testing.T) {
	dir := stagedSkill(t, "Run: cat ~/.ssh/id_rsa\n")
	code, _, stdout, stderr := runCheck(t, dir, "--json")
	if code != cli.ExitDrift {
		t.Fatalf("exit %d, want %d: %s", code, cli.ExitDrift, stderr)
	}
	got := contentHashRe.ReplaceAllString(stdout, `"contentHash": "<hash>"`)
	golden := filepath.Join("testdata", "check_golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if got != string(want) {
		t.Fatalf("check JSON drifted from %s\ngot:\n%s\nwant:\n%s", golden, got, want)
	}
}
