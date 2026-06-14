package sign

import (
	"testing"

	"github.com/alexverify/assay/internal/domain/lockfile"
)

func approvedEntry(id, hash string) lockfile.Entry {
	e := lockfile.Entry{}
	e.ID = id
	e.ContentHash = hash
	e.Approval = &lockfile.Approval{Status: "approved", By: "alice"}
	return e
}

func TestSignVerifyApprovalRoundTrip(t *testing.T) {
	s, _ := Generate()
	e := approvedEntry("a1", "sha256-abc")

	sig, err := s.SignApproval(e)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	e.Approval.Sig = sig

	kr := NewKeyring()
	_ = kr.AddBase64(s.PublicKeyBase64())
	if err := kr.VerifyApproval(e); err != nil {
		t.Fatalf("VerifyApproval of a freshly signed approval failed: %v", err)
	}
}

func TestVerifyApprovalRejectsContentChange(t *testing.T) {
	s, _ := Generate()
	e := approvedEntry("a1", "sha256-original")
	sig, _ := s.SignApproval(e)
	e.Approval.Sig = sig

	kr := NewKeyring()
	_ = kr.AddBase64(s.PublicKeyBase64())

	// Simulate a rug pull: content hash moves after approval.
	e.ContentHash = "sha256-tampered"
	if err := kr.VerifyApproval(e); err == nil {
		t.Fatal("VerifyApproval must reject an approval whose content changed")
	}
}

func TestVerifyApprovalRejectsForgedAndUntrusted(t *testing.T) {
	signer, _ := Generate()
	mallory, _ := Generate()
	e := approvedEntry("a1", "sha256-abc")
	sig, _ := mallory.SignApproval(e)
	e.Approval.Sig = sig

	kr := NewKeyring()
	_ = kr.AddBase64(signer.PublicKeyBase64()) // mallory not trusted
	if err := kr.VerifyApproval(e); err == nil {
		t.Fatal("VerifyApproval must reject a signature from an untrusted key")
	}

	// Hand-added approval with no signature at all.
	e.Approval.Sig = ""
	if err := kr.VerifyApproval(e); err == nil {
		t.Fatal("VerifyApproval must reject an unsigned approval")
	}
}

func TestVerifyApprovalNoApproval(t *testing.T) {
	kr := NewKeyring()
	if err := kr.VerifyApproval(lockfile.Entry{}); err == nil {
		t.Fatal("VerifyApproval must error when there is no approval")
	}
}
