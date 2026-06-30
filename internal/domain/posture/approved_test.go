package posture

import (
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// ApprovedSet trusts an approval only when it is both approved and signed; a
// pending status or an unsigned sign-off must not grant trust.
func TestApprovedSet(t *testing.T) {
	entry := func(id string, ap *lockfile.Approval) lockfile.Entry {
		return lockfile.Entry{Artifact: artifact.Artifact{ID: id}, Approval: ap}
	}
	lf := lockfile.Lockfile{Artifacts: []lockfile.Entry{
		entry("signed-approved", &lockfile.Approval{Status: "approved", Sig: "ed25519:x"}),
		entry("approved-unsigned", &lockfile.Approval{Status: "approved"}),
		entry("signed-pending", &lockfile.Approval{Status: "pending", Sig: "ed25519:y"}),
		entry("no-approval", nil),
	}}

	got := ApprovedSet(lf)
	if !got["signed-approved"] {
		t.Errorf("a signed, approved artifact must be in the trusted set")
	}
	if got["approved-unsigned"] || got["signed-pending"] || got["no-approval"] {
		t.Errorf("only signed-and-approved counts: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected exactly one approved id, got %v", got)
	}
}

// Line phrases the drift clause for none / one / many — each is a distinct
// branch the terminal summary depends on.
func TestPostureLineDriftPhrasing(t *testing.T) {
	cases := []struct {
		drifted int
		want    string
	}{
		{0, "nothing has drifted"},
		{1, "1 artifact has drifted"},
		{3, "3 artifacts have drifted"},
	}
	for _, c := range cases {
		got := Posture{Total: 5, Tools: 1, Drifted: c.drifted}.Line()
		if !strings.Contains(got, c.want) {
			t.Errorf("Drifted=%d: Line = %q, want substring %q", c.drifted, got, c.want)
		}
	}
}
