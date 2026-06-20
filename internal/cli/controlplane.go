package cli

import (
	"context"
	"fmt"

	"github.com/alexverify/eyebrow/internal/adapters/policystore"
	"github.com/alexverify/eyebrow/internal/adapters/sign"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/policy"
)

// resolvePolicy returns the policy to enforce: the control plane's when a server
// is configured and serves one for the org, else the local policy file. A
// server error or a missing server policy falls back to local — the same
// advisory-feed contract the offline feeds follow. The server policy is
// normalized exactly as policystore.Load normalizes the local one, so the two
// paths gate identically.
func (a *App) resolvePolicy(ctx context.Context, server, token, localPath string) (policy.Policy, error) {
	if server != "" {
		p, ok, err := client.New(server, token).Policy(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(a.Stderr, "warning: control plane policy unavailable (%v); using local %s\n", err, localPath)
		case ok:
			return p.Normalize(), nil
		}
	}
	p, _, err := policystore.Load(localPath)
	return p, err
}

// lockfileVerifierWithServer builds the trust set like lockfileVerifier, then
// adds the org's trusted keys pulled from the control plane (opt-in). A server
// error is a warning, never a failure: verification falls back to the local
// trusted-keys registry.
func (a *App) lockfileVerifierWithServer(ctx context.Context, projectRegistry, server, token string) (ports.LockfileVerifier, error) {
	kr, err := sign.LoadKeyring(projectRegistry, a.trustedKeysPath())
	if err != nil {
		return nil, err
	}
	if server != "" {
		if keys, err := client.New(server, token).TrustedKeys(ctx); err == nil {
			for _, k := range keys {
				if e := kr.AddBase64(k.Key); e != nil {
					fmt.Fprintf(a.Stderr, "warning: control plane key skipped: %v\n", e)
				}
			}
		} else {
			fmt.Fprintf(a.Stderr, "warning: control plane keys unavailable (%v)\n", err)
		}
	}
	// Same zero-trust fallback as lockfileVerifier: a lone user with no committed
	// or server registry verifies their own signatures with no ceremony.
	if kr.Len() == 0 {
		if s, err := sign.Load(a.keyPath()); err == nil {
			if err := kr.AddBase64(s.PublicKeyBase64()); err != nil {
				return nil, err
			}
		}
	}
	return kr, nil
}
