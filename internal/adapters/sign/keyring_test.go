package sign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexverify/agentguard/internal/domain/artifact"
	"github.com/alexverify/agentguard/internal/domain/lockfile"
)

func testLockfile() lockfile.Lockfile {
	return lockfile.Build([]artifact.Artifact{{
		ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "demo", ContentHash: "sha256-x",
	}}, time.Unix(0, 0).UTC(), "agentguard/test")
}

func TestKeyringVerifiesAnyTrustedKey(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()

	kr := NewKeyring()
	if err := kr.AddBase64(alice.PublicKeyBase64()); err != nil {
		t.Fatalf("AddBase64(alice): %v", err)
	}
	if err := kr.AddBase64(bob.PublicKeyBase64()); err != nil {
		t.Fatalf("AddBase64(bob): %v", err)
	}

	signed, err := bob.SignLockfile(testLockfile())
	if err != nil {
		t.Fatalf("SignLockfile: %v", err)
	}
	if err := kr.VerifyLockfile(signed); err != nil {
		t.Fatalf("VerifyLockfile must accept a signature from any trusted key: %v", err)
	}
}

func TestKeyringRejectsUntrustedKey(t *testing.T) {
	alice, _ := Generate()
	mallory, _ := Generate()

	kr := NewKeyring()
	_ = kr.AddBase64(alice.PublicKeyBase64())

	signed, _ := mallory.SignLockfile(testLockfile())
	if err := kr.VerifyLockfile(signed); err == nil {
		t.Fatal("VerifyLockfile must reject a signature from an untrusted key")
	}
}

func TestKeyringRejectsUnsignedAndEmpty(t *testing.T) {
	kr := NewKeyring()
	if err := kr.VerifyLockfile(testLockfile()); err == nil {
		t.Fatal("an empty keyring must not verify anything")
	}
	alice, _ := Generate()
	_ = kr.AddBase64(alice.PublicKeyBase64())
	if err := kr.VerifyLockfile(testLockfile()); err == nil {
		t.Fatal("VerifyLockfile must reject an unsigned lockfile")
	}
}

func TestKeyringAddBase64Malformed(t *testing.T) {
	kr := NewKeyring()
	if err := kr.AddBase64("not-base64!!"); err == nil {
		t.Fatal("AddBase64 must reject malformed base64")
	}
	if err := kr.AddBase64("c2hvcnQ="); err == nil { // valid base64, wrong length
		t.Fatal("AddBase64 must reject a key of the wrong size")
	}
}

func TestLoadKeyringParsesFileFormat(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()

	path := filepath.Join(t.TempDir(), "trusted_keys")
	content := strings.Join([]string{
		"# team keys",
		"",
		alice.PublicKeyBase64() + " alice@laptop",
		bob.PublicKeyBase64(),
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	kr, err := LoadKeyring(path, filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("LoadKeyring: %v (missing files must be skipped)", err)
	}
	if kr.Len() != 2 {
		t.Fatalf("Len = %d, want 2", kr.Len())
	}
	if !kr.Contains(alice.PublicKeyBase64()) || !kr.Contains(bob.PublicKeyBase64()) {
		t.Fatal("keyring must contain both parsed keys")
	}
}

func TestLoadKeyringMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_keys")
	if err := os.WriteFile(path, []byte("garbage-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("LoadKeyring must error on a malformed key line")
	}
}

func TestAppendTrustedKey(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()
	path := filepath.Join(t.TempDir(), "sub", "trusted_keys")

	if err := AppendTrustedKey(path, alice.PublicKeyBase64(), "alice"); err != nil {
		t.Fatalf("AppendTrustedKey (create): %v", err)
	}
	if err := AppendTrustedKey(path, bob.PublicKeyBase64(), ""); err != nil {
		t.Fatalf("AppendTrustedKey (append): %v", err)
	}
	// Re-adding an existing key is a no-op, not a duplicate.
	if err := AppendTrustedKey(path, alice.PublicKeyBase64(), "alice-again"); err != nil {
		t.Fatalf("AppendTrustedKey (dup): %v", err)
	}

	kr, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if kr.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (no duplicates)", kr.Len())
	}
}

func TestAppendTrustedKeyRejectsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_keys")
	if err := AppendTrustedKey(path, "nope", ""); err == nil {
		t.Fatal("AppendTrustedKey must reject a malformed key")
	}
}
