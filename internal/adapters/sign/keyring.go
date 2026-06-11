package sign

import (
	"bufio"
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

// Keyring verifies lockfile signatures against a set of trusted ed25519 public
// keys, satisfying ports.LockfileVerifier. A signature is accepted if it
// verifies under ANY trusted key — the signature format does not name its key,
// and trying each is cheap at team scale.
//
// Keys come from trusted-keys files: one base64 public key per line, with an
// optional trailing label and '#' comments (a minimal authorized_keys). Teams
// commit one next to the lockfile; personal additions live under ~/.agentguard.
type Keyring struct {
	keys []ed25519.PublicKey
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{} }

// parseKey decodes a base64 ed25519 public key.
func parseKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("bad key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad key size %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// AddBase64 adds a base64-encoded public key to the keyring.
func (k *Keyring) AddBase64(b64 string) error {
	pub, err := parseKey(b64)
	if err != nil {
		return err
	}
	if !k.Contains(b64) {
		k.keys = append(k.keys, pub)
	}
	return nil
}

// Len reports the number of trusted keys.
func (k *Keyring) Len() int { return len(k.keys) }

// Contains reports whether the base64-encoded key is already trusted.
func (k *Keyring) Contains(b64 string) bool {
	for _, key := range k.keys {
		if base64.StdEncoding.EncodeToString(key) == b64 {
			return true
		}
	}
	return false
}

// VerifyLockfile checks the lockfile signature against every trusted key and
// accepts the first match. It errors when the lockfile is unsigned, the keyring
// is empty, or no trusted key verifies the signature.
func (k *Keyring) VerifyLockfile(lf lockfile.Lockfile) error {
	if lf.Sig == "" {
		return errors.New("lockfile is not signed")
	}
	if len(k.keys) == 0 {
		return errors.New("no trusted keys configured")
	}
	canon, err := lockfile.CanonicalBytes(lf)
	if err != nil {
		return err
	}
	for _, pub := range k.keys {
		if New(nil, pub).Verify(canon, lf.Sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("signature does not match any of the %d trusted key(s)", len(k.keys))
}

// LoadKeyring builds a keyring from trusted-keys files. Missing files are
// skipped (an absent registry is not an error — verification will then fail
// with "no trusted keys"); malformed lines are.
func LoadKeyring(paths ...string) (*Keyring, error) {
	kr := NewKeyring()
	for _, path := range paths {
		f, err := os.Open(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		err = parseKeyLines(f, func(b64 string) error {
			if e := kr.AddBase64(b64); e != nil {
				return fmt.Errorf("%s: %w", path, e)
			}
			return nil
		})
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return kr, nil
}

// parseKeyLines scans the trusted-keys format: blank lines and '#' comments are
// ignored; the first field of each remaining line is the base64 key, the rest
// an optional label.
func parseKeyLines(f *os.File, add func(b64 string) error) error {
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := add(strings.Fields(line)[0]); err != nil {
			return err
		}
	}
	return sc.Err()
}

// AppendTrustedKey adds a public key (with an optional label) to a trusted-keys
// file, creating the file and its directory if needed. Re-adding a key already
// present is a no-op.
func AppendTrustedKey(path, b64, label string) error {
	if _, err := parseKey(b64); err != nil {
		return err
	}
	existing, err := LoadKeyring(path)
	if err != nil {
		return err
	}
	if existing.Contains(b64) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line := b64
	if label != "" {
		line += " " + label
	}
	_, err = fmt.Fprintln(f, line)
	return err
}
