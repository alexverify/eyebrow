package sign

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/lockfile"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data := []byte("sha256-deadbeef")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(data, sig); err != nil {
		t.Fatalf("Verify of valid signature failed: %v", err)
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	s, _ := Generate()
	sig, _ := s.Sign([]byte("original"))
	if err := s.Verify([]byte("tampered"), sig); err == nil {
		t.Fatal("Verify must reject a signature over different data")
	}
}

func TestVerifyRejectsWrongScheme(t *testing.T) {
	s, _ := Generate()
	if err := s.Verify([]byte("x"), "cosign:abc"); err == nil {
		t.Fatal("Verify must reject an unknown signature scheme")
	}
}

func TestSignWithoutPrivateKey(t *testing.T) {
	s := New(nil, nil)
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("Sign without a private key must error")
	}
}

func TestLoadOrCreatePersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "key")
	a, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate (create): %v", err)
	}
	b, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate (load): %v", err)
	}
	if a.PublicKeyBase64() != b.PublicKeyBase64() {
		t.Fatal("LoadOrCreate must return the same persisted key")
	}
}

func TestSignVerifyLockfileRoundTrip(t *testing.T) {
	s, _ := Generate()
	lf := lockfile.Build([]artifact.Artifact{{
		ID: "a1", Tool: "claude-code", Type: artifact.TypeSkill, Name: "demo", ContentHash: "sha256-x",
	}}, time.Unix(0, 0).UTC(), "assay/test")

	signed, err := s.SignLockfile(lf)
	if err != nil {
		t.Fatalf("SignLockfile: %v", err)
	}
	if signed.Sig == "" {
		t.Fatal("SignLockfile did not set a signature")
	}
	if err := s.VerifyLockfile(signed); err != nil {
		t.Fatalf("VerifyLockfile of freshly signed lockfile failed: %v", err)
	}

	// Tamper after signing: verification must fail.
	signed.Artifacts[0].ContentHash = "sha256-tampered"
	if err := s.VerifyLockfile(signed); err == nil {
		t.Fatal("VerifyLockfile must reject a tampered lockfile")
	}
}

func TestVerifyLockfileUnsigned(t *testing.T) {
	s, _ := Generate()
	if err := s.VerifyLockfile(lockfile.Lockfile{}); err == nil {
		t.Fatal("VerifyLockfile must error on an unsigned lockfile")
	}
}
