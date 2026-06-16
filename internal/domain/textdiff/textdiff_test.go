package textdiff

import "testing"

// ops renders a diff as a compact "<op><text>" slice for assertions.
func ops(lines []Line) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = string(l.Op) + l.Text
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("diff length = %d, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q\n got: %v\nwant: %v", i, got[i], want[i], got, want)
		}
	}
}

func TestLinesModifyOneLine(t *testing.T) {
	old := "a\nb\nc"
	new := "a\nB\nc"
	eq(t, ops(Lines(old, new)), []string{" a", "-b", "+B", " c"})
}

func TestLinesPureInsert(t *testing.T) {
	eq(t, ops(Lines("a\nc", "a\nb\nc")), []string{" a", "+b", " c"})
}

func TestLinesPureDelete(t *testing.T) {
	eq(t, ops(Lines("a\nb\nc", "a\nc")), []string{" a", "-b", " c"})
}

func TestLinesIdentical(t *testing.T) {
	d := Lines("a\nb\n", "a\nb")
	for _, l := range d {
		if l.Op != Equal {
			t.Fatalf("a trailing-newline-only difference must be all-equal, got %v", ops(d))
		}
	}
}

func TestLinesEmptySides(t *testing.T) {
	eq(t, ops(Lines("", "x")), []string{"+x"})
	eq(t, ops(Lines("x", "")), []string{"-x"})
	if len(Lines("", "")) != 0 {
		t.Errorf("empty→empty should be an empty diff")
	}
}

func TestLineNumbers(t *testing.T) {
	d := Lines("a\nb\nc", "a\nB\nc")
	// " a" old1/new1, "-b" old2, "+B" new2, " c" old3/new3
	if d[1].Op != Delete || d[1].OldLine != 2 || d[1].NewLine != 0 {
		t.Errorf("delete line numbers wrong: %+v", d[1])
	}
	if d[2].Op != Insert || d[2].NewLine != 2 || d[2].OldLine != 0 {
		t.Errorf("insert line numbers wrong: %+v", d[2])
	}
	if d[3].OldLine != 3 || d[3].NewLine != 3 {
		t.Errorf("trailing context line numbers wrong: %+v", d[3])
	}
}

func TestCount(t *testing.T) {
	s := Count(Lines("a\nb\nc", "a\nB\nC\nd"))
	if s.Added == 0 || s.Removed == 0 {
		t.Errorf("expected both additions and removals, got %+v", s)
	}
}

func TestBinary(t *testing.T) {
	if !Binary("ELF\x00\x01") {
		t.Errorf("content with a NUL byte should be detected as binary")
	}
	if Binary("plain text\nlines") {
		t.Errorf("plain text must not be flagged binary")
	}
}

func TestHunksGroupsWithContext(t *testing.T) {
	// Change line 5 and line 9: with context 1 these are two separate hunks;
	// with context 3 their context windows overlap and merge into one.
	a := "x1\nx2\nx3\nx4\nMID\nx6\nx7\nx8\nEND\nx10"
	b := "x1\nx2\nx3\nx4\nMID2\nx6\nx7\nx8\nEND2\nx10"
	d := Lines(a, b)

	if h := Hunks(d, 1); len(h) != 2 {
		t.Errorf("context=1 should give 2 hunks, got %d", len(h))
	}
	if h := Hunks(d, 3); len(h) != 1 {
		t.Errorf("context=3 should merge into 1 hunk, got %d", len(h))
	}
}

func TestHunksHeaderCounts(t *testing.T) {
	d := Lines("a\nb\nc", "a\nB\nc")
	h := Hunks(d, 0)
	if len(h) != 1 {
		t.Fatalf("one changed region → one hunk, got %d", len(h))
	}
	// just the -b/+B pair, no context
	if h[0].OldStart != 2 || h[0].OldCount != 1 || h[0].NewStart != 2 || h[0].NewCount != 1 {
		t.Errorf("hunk header wrong: %+v", h[0])
	}
}

func TestHunksNoChangesNoHunks(t *testing.T) {
	if h := Hunks(Lines("a\nb", "a\nb"), 3); len(h) != 0 {
		t.Errorf("an unchanged file should produce no hunks, got %d", len(h))
	}
}
