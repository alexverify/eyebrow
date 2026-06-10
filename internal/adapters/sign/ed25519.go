// Package sign implements detached ed25519 signatures over canonical bytes,
// satisfying ports.Signer. The signature format is "ed25519:<base64>" so the
// algorithm is self-describing and a future cosign/Sigstore adapter can use a
// different prefix without ambiguity.
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const prefix = "ed25519:"

// Signer signs and verifies with an ed25519 key pair. The private key may be
// nil for a verify-only instance.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// New returns a Signer from an existing key pair. Pass a nil private key to
// build a verify-only signer.
func New(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Signer {
	return &Signer{priv: priv, pub: pub}
}

// Generate creates a fresh ed25519 key pair wrapped in a Signer.
func Generate() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil) // crypto/rand
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub}, nil
}

// Sign returns a detached signature over data.
func (s *Signer) Sign(data []byte) (string, error) {
	if s.priv == nil {
		return "", errors.New("sign: no private key configured")
	}
	sig := ed25519.Sign(s.priv, data)
	return prefix + base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks a detached signature against data using the configured public
// key.
func (s *Signer) Verify(data []byte, sig string) error {
	if s.pub == nil {
		return errors.New("verify: no public key configured")
	}
	raw, ok := strings.CutPrefix(sig, prefix)
	if !ok {
		return fmt.Errorf("verify: unexpected signature scheme in %q", sig)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("verify: bad signature encoding: %w", err)
	}
	if !ed25519.Verify(s.pub, data, decoded) {
		return errors.New("verify: signature does not match")
	}
	return nil
}

// PublicKeyBase64 returns the base64-encoded public key, suitable for storing
// in a trust registry.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.pub)
}
