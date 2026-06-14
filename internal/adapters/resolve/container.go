package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/alexverify/assay/internal/app/ports"
	"github.com/alexverify/assay/internal/domain/artifact"
	"github.com/alexverify/assay/internal/domain/finding"
	"github.com/alexverify/assay/internal/platform/run"
)

// Container resolves container-image MCP sources. The image reference is the
// integrity anchor (ideally pinned to an @sha256: digest); a cosign signature,
// when present and verifiable, satisfies the top provenance rung. Like git,
// the tree is not hashed locally — the pinned ref makes drift detectable.
type Container struct {
	Runner run.Runner
}

// NewContainer builds a Container resolver.
func NewContainer(r run.Runner) Container { return Container{Runner: r} }

// cosignPredicate marks an image whose signature cosign verified, recorded on
// Source.Provenance so the ladder's top rung is met.
const cosignPredicate = "sigstore-cosign"

// Resolve satisfies ports.Resolver.
func (c Container) Resolve(ctx context.Context, src artifact.Source) (ports.Resolution, error) {
	ref := strings.TrimSpace(src.Ref)
	if ref == "" {
		ref = strings.TrimSpace(src.Command)
	}
	if ref == "" {
		return ports.Resolution{}, fmt.Errorf("container: empty image reference")
	}

	var warnings []finding.Finding
	if !strings.Contains(ref, "@sha256:") {
		warnings = append(warnings, finding.Finding{
			RuleID: "UNPINNED-CONTAINER", Severity: finding.SeverityHigh, OWASP: "ASK-02",
			Explanation: fmt.Sprintf("container image %q is not pinned to a digest; pin to @sha256:… so the image is locked", ref),
		})
	}

	res := ports.Resolution{PinnedRef: ref, Warnings: warnings}
	// cosign fetches signatures from the registry, so verification works without
	// pulling the image. Exit zero means a signature verified. A missing cosign,
	// an unsigned image, or a verification failure all degrade to no provenance
	// plus an informational finding — never a hard error.
	if _, verr := c.Runner.Run(ctx, "cosign", "verify", ref); verr == nil {
		res.Provenance = cosignPredicate
	} else {
		res.Warnings = append(res.Warnings, finding.Finding{
			RuleID: "CONTAINER-UNSIGNED", Severity: finding.SeverityInfo, OWASP: "ASK-04",
			Explanation: "container image signature not verified by cosign (image unsigned or cosign unavailable)",
		})
	}
	return res, nil
}
