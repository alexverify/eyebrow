package sign

import (
	"errors"
	"fmt"

	"github.com/alexverify/assay/internal/domain/lockfile"
)

// SignApproval signs an entry's approval-binding bytes (ID + content hash),
// returning the detached signature to store in Approval.Sig.
func (s *Signer) SignApproval(e lockfile.Entry) (string, error) {
	return s.Sign(lockfile.ApprovalSigningBytes(e))
}

// VerifyApproval checks that an entry's approval carries a signature from a
// trusted key over the entry's current ID and content hash. It errors when
// the approval is absent, unsigned, or signed by an untrusted key — and,
// because the signature commits to the content hash, when the content changed
// after approval.
func (k *Keyring) VerifyApproval(e lockfile.Entry) error {
	if e.Approval == nil || e.Approval.Sig == "" {
		return errors.New("approval is not signed")
	}
	if len(k.keys) == 0 {
		return errors.New("no trusted keys configured")
	}
	canon := lockfile.ApprovalSigningBytes(e)
	for _, pub := range k.keys {
		if New(nil, pub).Verify(canon, e.Approval.Sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("approval signature for %s does not match any trusted key", e.ID)
}
