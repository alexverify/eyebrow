package doctor

import (
	"strings"
	"testing"
)

func TestInfoDoesNotCountAsWarning(t *testing.T) {
	r := Report{}.Add("tools", StatusOK, "found 3").Add("hooks", StatusInfo, "none installed")
	if !r.Healthy() {
		t.Error("a report with only ok/info checks must be healthy")
	}
	if got := r.Warnings(); got != 0 {
		t.Errorf("warnings = %d, want 0", got)
	}
}

func TestWarningsAreCounted(t *testing.T) {
	r := Report{}.Add("a", StatusWarn, "x").Add("b", StatusOK, "y").Add("c", StatusWarn, "z")
	if r.Healthy() {
		t.Error("a report with warnings is not healthy")
	}
	if got := r.Warnings(); got != 2 {
		t.Errorf("warnings = %d, want 2", got)
	}
}

func TestRenderShowsEachCheckAndSummary(t *testing.T) {
	out := Report{}.
		Add("tools", StatusOK, "discovered 3").
		Add("lockfile", StatusWarn, "missing").
		Render()
	for _, want := range []string{"tools", "discovered 3", "lockfile", "missing", "ok", "warn", "1 warning"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n%s", want, out)
		}
	}
}

func TestRenderAllGoodWhenHealthy(t *testing.T) {
	out := Report{}.Add("x", StatusOK, "fine").Render()
	if !strings.Contains(out, "all good") {
		t.Errorf("want 'all good' summary, got:\n%s", out)
	}
}

func TestRenderPluralizesWarnings(t *testing.T) {
	out := Report{}.Add("a", StatusWarn, "x").Add("b", StatusWarn, "y").Render()
	if !strings.Contains(out, "2 warnings") {
		t.Errorf("want '2 warnings', got:\n%s", out)
	}
}
