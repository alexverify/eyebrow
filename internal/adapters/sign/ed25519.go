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
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/agentguard/internal/domain/lockfile"
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

// Load reads an ed25519 private key from path (base64-encoded). It returns the
// underlying fs error (e.g. fs.ErrNotExist) when the file is absent.
func Load(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if derr != nil {
		return nil, fmt.Errorf("key %s: %w", path, derr)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key %s: unexpected size %d", path, len(raw))
	}
	priv := ed25519.PrivateKey(raw)
	return New(priv, priv.Public().(ed25519.PublicKey)), nil
}

// LoadOrCreate loads an ed25519 private key from path, or generates one and
// saves it (0600) if the file does not exist. The parent directory is created
// 0700. This gives a stable local signing identity.
func LoadOrCreate(path string) (*Signer, error) {
	if s, err := Load(path); err == nil {
		return s, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	s, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(s.priv)
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// SignLockfile signs the lockfile's canonical bytes and returns a copy with the
// signature set.
func (s *Signer) SignLockfile(lf lockfile.Lockfile) (lockfile.Lockfile, error) {
	canon, err := lockfile.CanonicalBytes(lf)
	if err != nil {
		return lf, err
	}
	sig, err := s.Sign(canon)
	if err != nil {
		return lf, err
	}
	lf.Sig = sig
	return lf, nil
}

// VerifyLockfile checks the lockfile's signature against this signer's public
// key. It errors if the lockfile is unsigned or the signature does not match.
func (s *Signer) VerifyLockfile(lf lockfile.Lockfile) error {
	if lf.Sig == "" {
		return errors.New("lockfile is not signed")
	}
	canon, err := lockfile.CanonicalBytes(lf)
	if err != nil {
		return err
	}
	return s.Verify(canon, lf.Sig)
}
